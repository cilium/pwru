package ebpfsl

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf-sl/internal"
	"github.com/cilium/ebpf-sl/signable"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/sys"
	"golang.org/x/sys/unix"
)

func NewLoaderFromSpec(spec *ebpf.CollectionSpec) (*signable.Loader, error) {
	builder, err := newBuilder()
	if err != nil {
		return nil, fmt.Errorf("create builder: %w", err)
	}

	if err := builder.init(); err != nil {
		return nil, fmt.Errorf("initialize builder: %w", err)
	}

	// Add maps in sorted order to ensure deterministic output.
	for _, mapName := range slices.Sorted(maps.Keys(spec.Maps)) {
		m := spec.Maps[mapName]
		if err := builder.addMap(m); err != nil {
			return nil, fmt.Errorf("add map %s: %w", m.Name, err)
		}
	}

	// Add programs in sorted order to ensure deterministic output.
	for _, progName := range slices.Sorted(maps.Keys(spec.Programs)) {
		prog := spec.Programs[progName]
		if err := builder.addProgram(prog); err != nil {
			return nil, fmt.Errorf("add program %s: %w", prog.Name, err)
		}
	}

	sl, err := builder.finalize()
	if err != nil {
		return nil, fmt.Errorf("finalize builder: %w", err)
	}

	return sl, nil
}

// builder builds a signable loader.
// The signable loader that is created has an external and internal contract.
//
// The external contract is that the expected context has the shape of [signable.LoaderContext].
// Pre-existing file descriptors such as those from re-used maps are passed in through [signable.LoaderContext.FDs].
// The result of syscalls that return file descriptors are returned in [signable.LoaderContext.FDs], these can
// be the actual created file descriptors or the error code of the syscall if it failed.
// It is up to the userspace loader to chose to close any file descriptors of a partially failed load, or to re-try with
// different load-time parameters (log buffer resize).
// The metadata map should be passed via the fdArray of the loader program in index 0.
//
// The internal contract assigns special purpose to certain registers.
// R6 contains the pointer to the context.
// R7 contains the result of the last syscall, containing a file descriptor or error code.
type builder struct {
	metadata   []byte
	fdSlots    []signable.FDSlot
	progIdx    int
	fdArrayBuf mdOffset
	funcs      []*bpfFunc
}

func newBuilder() (*builder, error) {
	b := &builder{}

	// Describe a entrypoint equal to: int ebpf_sl(void *ctx)
	b.funcs = append(b.funcs, &bpfFunc{
		btf: &btf.Func{
			Name:    "ebpf_sl",
			Linkage: btf.StaticFunc,
			Type: &btf.FuncProto{
				Return: &btf.Int{Size: 4, Encoding: btf.Signed},
				Params: []btf.FuncParam{
					btf.FuncParam{Name: "ctx", Type: &btf.Pointer{
						Target: &btf.Int{Size: 1, Encoding: btf.Char},
					}},
				},
			},
		},
	})

	return b, nil
}

const (
	metadataMapIdx = 0

	ctxReg = asm.R6

	fdBytes = 4 // A file descriptor is always a 32 bit integer
)

var (
	Debug = false

	ErrNotImplemented = fmt.Errorf("not implemented")
)

func (b *builder) init() error {
	b.emit(
		// Store the context pointer in R6 for later use.
		asm.Mov.Reg(ctxReg, asm.R1),
	)

	// When passing map FDs to a program its easier to use the fdArray, but the fdArray is not allowed to be a pointer
	// to the context, so we allocate an array of 64 FDs in the metadata map which we can populate with map FDs and then
	// pass to the program. 64 because that is the max number of maps that a program can have.
	b.fdArrayBuf = b.addData(make([]byte, fdBytes*64))

	b.initLoadBTF()

	return nil
}

const loadBTFFuncName = "load_btf"

// initLoadBTF emits a re-usable static function for loader BTF. The BPF-to-BPF function takes a pointer to a BTF blob
// and size of that blob as arguments, and returns a file descriptor for the loaded BTF object.
func (b *builder) initLoadBTF() {
	// int load_btf(void *btf_blob, uint32_t btf_size)
	loadBTF := &bpfFunc{
		btf: &btf.Func{
			Name:    loadBTFFuncName,
			Linkage: btf.StaticFunc,
			Type: &btf.FuncProto{
				Return: &btf.Int{Size: 4, Encoding: btf.Signed},
				Params: []btf.FuncParam{
					btf.FuncParam{Name: "btf_blob", Type: &btf.Pointer{
						Target: &btf.Int{Size: 1, Encoding: btf.Char},
					}},
					btf.FuncParam{Name: "btf_size", Type: &btf.Int{Size: 4, Encoding: btf.Unsigned}},
				},
			},
		},
	}
	b.funcs = append(b.funcs, loadBTF)

	// Allocate a buffer for the BTF load attributes in the metadata map.
	btfAttrOff := b.addData(make([]byte, sizeOf[sys.BtfLoadAttrRaw]()))

	loadBTF.emit(
		// Move arg2 into R4, since we need to modify R2 to point to the BTF load attr struct.
		asm.Mov.Reg(asm.R4, asm.R2),
		// Load ptr to btf load attr struct from metadata map, put in R2 (second argument to sys_bpf).
		asm.LoadMapValueIdx(asm.R2, metadataMapIdx, uint32(btfAttrOff)).WithSource(asm.Comment("btf load attr ptr")),
		// Load the btf blob pointer from R1 into the btf load attr struct.
		asm.StoreMem(asm.R2, offsetOf[sys.BtfLoadAttrRaw]("Btf"), asm.R1, asm.DWord),
		// Load the btf size from R4 into the btf load attr struct.
		asm.StoreMem(asm.R2, offsetOf[sys.BtfLoadAttrRaw]("BtfSize"), asm.R4, asm.Word),
		// Load the syscall number for BPF_BTF_LOAD into R1, and the size of the btf load attr struct into R3.
		asm.Mov.Imm(asm.R1, int32(sys.BPF_BTF_LOAD)),
		asm.Mov.Imm(asm.R3, sizeOf[sys.BtfLoadAttrRaw]()),
		asm.FnSysBpf.Call(),
		asm.Return(),
	)
}

const createMapFuncTpl = "create_map_%s"

func (b *builder) addMap(spec *ebpf.MapSpec) error {
	if spec.InnerMap != nil {
		return fmt.Errorf("map %s has inner map, which is not supported", spec.Name)
	}
	if spec.Contents != nil {
		return fmt.Errorf("map %s has KV contents, which is not supported", spec.Name)
	}

	mapFunc := &bpfFunc{
		btf: &btf.Func{
			Name:    fmt.Sprintf(createMapFuncTpl, spec.Name),
			Linkage: btf.StaticFunc,
			Type: &btf.FuncProto{
				Return: &btf.Int{Size: 4, Encoding: btf.Signed},
				Params: []btf.FuncParam{{
					Name: "ctx",
					Type: &btf.Pointer{
						Target: &btf.Int{Size: 1, Encoding: btf.Char},
					},
				}},
			},
		},
	}
	b.funcs = append(b.funcs, mapFunc)

	mapFunc.emit(
		asm.Mov.Reg(ctxReg, asm.R1),
	)

	mapAttr := sys.MapCreateAttrRaw{
		MapType:    uint32(spec.Type),
		KeySize:    uint32(spec.KeySize),
		ValueSize:  uint32(spec.ValueSize),
		MaxEntries: uint32(spec.MaxEntries),
		MapFlags:   spec.Flags,
		MapName:    internal.MaybeFillObjName(spec.Name),
		MapExtra:   spec.MapExtra,
	}

	mapAttrBytes, err := binary.Append(nil, internal.NativeEndian, mapAttr)
	if err != nil {
		return fmt.Errorf("marshal map create attr: %w", err)
	}
	mapAttrOff := b.addData(mapAttrBytes)

	mapFDSlot := signable.FDSlot{
		Map: &spec.Name,
	}
	mapFDSlotIdx, err := b.allocFDSlot(mapFDSlot)
	if err != nil {
		return fmt.Errorf("allocate FD slot for map %s: %w", spec.Name, err)
	}

	skipLabel := fmt.Sprintf("skip_map_%s", spec.Name)

	mapFunc.emit(
		// Load FD from the context's FDs array at the allocated slot index
		asm.LoadMemSX(asm.R0, ctxReg, offsetOf[signable.LoaderContext]("FDs")+int16(int32(mapFDSlotIdx)*sizeOf[uint32]()), asm.Word),
		// If a valid FD is already present, skip the map creation, and return the cached FD.
		asm.JSGT.Imm(asm.R0, 0, skipLabel),
	)

	mapBtfBuilder, err := btf.NewBuilder(nil, nil)
	if err != nil {
		return fmt.Errorf("create BTF builder for map %s: %w", spec.Name, err)
	}
	var keyID, valueID btf.TypeID
	if spec.Key != nil {
		keyID, err = mapBtfBuilder.Add(spec.Key)
		if err != nil {
			return fmt.Errorf("add BTF key type for map %s: %w", spec.Name, err)
		}
	}
	if spec.Value != nil {
		valueID, err = mapBtfBuilder.Add(spec.Value)
		if err != nil {
			return fmt.Errorf("add BTF value type for map %s: %w", spec.Name, err)
		}
	}

	if !mapBtfBuilder.Empty() {
		mapBTFBytes, err := mapBtfBuilder.Marshal(nil, nil)
		if err != nil {
			return fmt.Errorf("marshal BTF for map %s: %w", spec.Name, err)
		}
		mapBTFBytesOff := b.addData(mapBTFBytes)

		mapFunc.emit(
			// Load ptr to mapBTFBytes into R1
			asm.LoadMapValueIdx(asm.R1, metadataMapIdx, uint32(mapBTFBytesOff)).WithSource(asm.Comment("btf ptr")),
			asm.Mov.Imm(asm.R2, int32(len(mapBTFBytes))),
			// Call the load_btf function to load the BTF and return a FD in R0.
			asm.Call.Label(loadBTFFuncName),
			// Move FD to R8, so we have access after the map create syscall.
			asm.Mov.Reg(asm.R8, asm.R0),
			// Check for error return, jump to return if so, skip map creation.
			asm.JSLT.Imm(asm.R0, 0, skipLabel),
		)
	}

	mapFunc.emit(
		// Load ptr to map create attr struct from metadata map, put in R2 (second argument to sys_bpf).
		asm.LoadMapValueIdx(asm.R2, metadataMapIdx, uint32(mapAttrOff)).WithSource(asm.Comment("map create attr ptr")),
	)

	if !mapBtfBuilder.Empty() {
		mapFunc.emit(
			// Load the BTF FD from R0 into the map create attr struct.
			asm.StoreMem(asm.R2, offsetOf[sys.MapCreateAttrRaw]("BtfFd"), asm.R0, asm.Word),
		)
		if keyID != 0 {
			mapFunc.emit(
				// Load the key type ID into the map create attr struct.
				asm.StoreImm(asm.R2, offsetOf[sys.MapCreateAttrRaw]("BtfKeyTypeId"), int64(keyID), asm.Word),
			)
		}
		if valueID != 0 {
			mapFunc.emit(
				// Load the value type ID into the map create attr struct.
				asm.StoreImm(asm.R2, offsetOf[sys.MapCreateAttrRaw]("BtfValueTypeId"), int64(valueID), asm.Word),
			)
		}
	}

	mapFunc.emit(
		// Load the syscall number for BPF_MAP_CREATE into R1, and the size of the map create attr struct into R3.
		asm.Mov.Imm(asm.R1, int32(sys.BPF_MAP_CREATE)),
		asm.Mov.Imm(asm.R3, sizeOf[sys.MapCreateAttrRaw]()),
		asm.FnSysBpf.Call(),
		// Copy the result into R7, so we keep access after BTF fd cleanup
		asm.Mov.Reg(asm.R7, asm.R0),
		// Write the result into the context's FDs array at the allocated slot index.
		asm.StoreMem(ctxReg, offsetOf[signable.LoaderContext]("FDs")+int16(int32(mapFDSlotIdx)*sizeOf[uint32]()), asm.R0, asm.Word),
	)

	if !mapBtfBuilder.Empty() {
		// Close BTF file descriptor after load, don't need it anymore.
		mapFunc.emit(
			asm.Mov.Reg(asm.R1, asm.R8),
			asm.FnSysClose.Call(),
			// Restore the map FD from R7 to R0, so we return the map FD.
			asm.Mov.Reg(asm.R0, asm.R7),
		)
	}

	mapFunc.emit(
		// Return from function.
		asm.Return().WithSymbol(skipLabel),
	)

	return nil
}

func (b *builder) addProgram(spec *ebpf.ProgramSpec) error {
	if spec.AttachTarget != nil {
		return fmt.Errorf("program %s has attach target %s, which is not supported", spec.Name, spec.AttachTarget)
	}

	if spec.AttachTo != "" {
		return fmt.Errorf("program %s has attach to %s, which is not supported", spec.Name, spec.AttachTo)
	}

	progAttr := sys.ProgLoadAttrRaw{
		ProgType:           uint32(spec.Type),
		ProgFlags:          spec.Flags,
		ProgName:           internal.MaybeFillObjName(spec.Name),
		ProgIfindex:        spec.Ifindex,
		ExpectedAttachType: uint32(spec.AttachType),
	}

	// Clone the instructions so we can modify them without affecting the original spec.
	insns := slices.Clone(spec.Instructions)

	type mapRef struct {
		mapName  string
		ctxFdIdx int16
	}
	fdArray := make([]mapRef, 0)

	// Find all map load instructions, rewrite them so they reference a index in the fdArray.
	// We will provide the fdArray in the metadata to it, so map index directly to b.fdSlots.
	iter := insns.Iterate()
	for iter.Next() {
		if !iter.Ins.IsLoadFromMap() || iter.Ins.Reference() == "" {
			continue
		}

		fdIdx := slices.IndexFunc(fdArray, func(mr mapRef) bool {
			return mr.mapName == iter.Ins.Reference()
		})
		if fdIdx == -1 {
			for i, slot := range b.fdSlots {
				if slot.Map == nil || *slot.Map != iter.Ins.Reference() {
					continue
				}

				fdIdx = len(fdArray)
				fdArray = append(fdArray, mapRef{mapName: iter.Ins.Reference(), ctxFdIdx: int16(i)})
				break
			}

			if fdIdx == -1 {
				return fmt.Errorf("map %q referenced but not found", iter.Ins.Reference())
			}
		}

		if err := associateMapIdx(iter.Ins, fdIdx); err != nil {
			return fmt.Errorf("associate map index for instruction %v: %w", iter.Ins, err)
		}
	}

	// Marshal instructions to bytes, and add them to the metadata map.
	var insnsBuf bytes.Buffer
	err := insns.Marshal(&insnsBuf, internal.NativeEndian)
	if err != nil {
		return fmt.Errorf("marshal instructions: %w", err)
	}
	insnsBytes := insnsBuf.Bytes()
	insnsOff := b.addData(insnsBytes)
	// Write the number of raw instructions to the prog load attr struct.
	progAttr.InsnCnt = uint32(len(insnsBytes) / asm.InstructionSize)

	// Marshal the prog load attr struct to bytes, and add it to the metadata map.
	progAttrBytes, err := binary.Append(nil, internal.NativeEndian, progAttr)
	if err != nil {
		return fmt.Errorf("marshal prog load attr: %w", err)
	}
	progAttrOff := b.addData(progAttrBytes)

	progBtfBuilder, err := btf.NewBuilder(nil, nil)
	if err != nil {
		return fmt.Errorf("create BTF builder for program %s: %w", spec.Name, err)
	}
	funcInfos, lineInfos, err := btf.MarshalExtInfos(insns, progBtfBuilder)
	if err != nil {
		return fmt.Errorf("marshal ext_infos for program %s: %w", spec.Name, err)
	}

	// Marshal the license string to bytes, and add it to the metadata map.
	licenseBytes, err := unix.ByteSliceFromString(spec.License)
	if err != nil {
		return fmt.Errorf("marshal license: %w", err)
	}
	licenseOff := b.addData(licenseBytes)

	progFDSlot := signable.FDSlot{
		Prog: &spec.Name,
	}
	progFDSlotIdx, err := b.allocFDSlot(progFDSlot)
	if err != nil {
		return fmt.Errorf("allocate FD slot for program %s: %w", spec.Name, err)
	}

	progLogOff := offsetOf[signable.LoaderContext]("ProgLogs") + // Offset of the ProgLogs array in the context
		int16(int32(b.progIdx)*sizeOf[signable.ProgramLog]()) // Offset of the current program's log struct in the ProgLogs array
	b.progIdx++

	skipLabel := fmt.Sprintf("skip_prog_%s", spec.Name)

	b.emit(
		// Load FD from the context's FDs array at the allocated slot index
		asm.LoadMemSX(asm.R1, ctxReg, offsetOf[signable.LoaderContext]("FDs")+int16(int32(progFDSlotIdx)*sizeOf[uint32]()), asm.Word),
		// If the FD is larger than 0 and non-negative, it is a valid FD and we can skip the program load.
		// This allows us to retry parts of the collection loading, specifically to resize the log buffer for programs that failed to load due to insufficient log buffer size.
		asm.JSGT.Imm(asm.R1, 0, skipLabel),
	)

	if len(fdArray) > 0 {
		// Populate the fdArray buffer in the metadata map with the map FDs from the context's FDs array.
		b.emit(asm.LoadMapValueIdx(asm.R8, metadataMapIdx, uint32(b.fdArrayBuf)).WithSource(asm.Comment("fd array ptr")))
		for i, mapRef := range fdArray {
			b.emit(
				// Call map creation function with ptr to ctx as first argument.
				asm.Mov.Reg(asm.R1, ctxReg),
				asm.Call.Label(fmt.Sprintf(createMapFuncTpl, mapRef.mapName)),
				// Copy the result into R7, in case we jump to the error case.
				asm.Mov.Reg(asm.R7, asm.R0),
				// Check for error return, and just to error label if so.
				asm.JSLT.Imm(asm.R7, 0, "error"),
				// Store the map FD into the fdArray in the metadata map.
				asm.StoreMem(asm.R8, int16(i)*fdBytes, asm.R0, asm.Word),
			)
		}
	}

	if !progBtfBuilder.Empty() {
		progBTFBytes, err := progBtfBuilder.Marshal(nil, nil)
		if err != nil {
			return fmt.Errorf("marshal BTF for program %s: %w", spec.Name, err)
		}
		progBTFBytesOff := b.addData(progBTFBytes)
		b.emit(
			asm.LoadMapValueIdx(asm.R1, metadataMapIdx, uint32(progBTFBytesOff)).WithSource(asm.Comment("btf ptr")),
			asm.Mov.Imm(asm.R2, int32(len(progBTFBytes))),
			asm.Call.Label(loadBTFFuncName),
			// Copy the result into R7, in case we jump to the error case.
			asm.Mov.Reg(asm.R7, asm.R0),
			// Check for error return, and just to error label if so.
			asm.JSLT.Imm(asm.R7, 0, "error"),
			// Copy the FD into R8, to preserve it after the program load syscall, so we can clean it up.
			asm.Mov.Reg(asm.R8, asm.R0),
		)
	}

	b.emit(
		// Load ptr to prog load attr struct from metadata map, put in R2 (second argument to sys_bpf).
		// It already contains all static fields, we just need to fill in the dynamic ones.
		asm.LoadMapValueIdx(asm.R2, metadataMapIdx, uint32(progAttrOff)).WithSource(asm.Comment("prog load attr ptr")),
		// Load ptr to instructions, write it to the prog load attr struct.
		asm.LoadMapValueIdx(asm.R1, metadataMapIdx, uint32(insnsOff)).WithSource(asm.Comment("prog insns ptr")),
		asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("Insns"), asm.R1, asm.DWord),
		// Load ptr to license, write it to the prog load attr struct.
		asm.LoadMapValueIdx(asm.R1, metadataMapIdx, uint32(licenseOff)).WithSource(asm.Comment("prog license ptr")),
		asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("License"), asm.R1, asm.DWord),
	)

	if len(fdArray) > 0 {
		b.emit(
			// Load ptr to fds in context into FdArray field of prog load attr struct.
			asm.LoadMapValueIdx(asm.R1, metadataMapIdx, uint32(b.fdArrayBuf)).WithSource(asm.Comment("fd array ptr")),
			asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("FdArray"), asm.R1, asm.DWord),
			asm.StoreImm(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("FdArrayCnt"), int64(len(fdArray)), asm.Word),
		)
	}

	if !progBtfBuilder.Empty() {
		b.emit(
			// Store the BTF FD returned from the load_btf call into the prog load attr struct.
			asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("ProgBtfFd"), asm.R7, asm.Word),
		)
		if len(funcInfos) > 0 {
			funcInfosOff := b.addData(funcInfos)
			b.emit(
				// Load ptr to func infos into the prog load attr struct.
				asm.LoadMapValueIdx(asm.R1, metadataMapIdx, uint32(funcInfosOff)).WithSource(asm.Comment("func infos ptr")),
				asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("FuncInfo"), asm.R1, asm.DWord),
				asm.StoreImm(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("FuncInfoCnt"), int64(uint32(len(funcInfos))/btf.FuncInfoSize), asm.Word),
				asm.StoreImm(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("FuncInfoRecSize"), int64(btf.FuncInfoSize), asm.Word),
			)
		}
		if len(lineInfos) > 0 {
			lineInfosOff := b.addData(lineInfos)
			b.emit(
				// Load ptr to line infos into the prog load attr struct.
				asm.LoadMapValueIdx(asm.R1, metadataMapIdx, uint32(lineInfosOff)).WithSource(asm.Comment("line infos ptr")),
				asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("LineInfo"), asm.R1, asm.DWord),
				asm.StoreImm(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("LineInfoCnt"), int64(uint32(len(lineInfos))/btf.LineInfoSize), asm.Word),
				asm.StoreImm(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("LineInfoRecSize"), int64(btf.LineInfoSize), asm.Word),
			)
		}
	}

	b.emit(
		// Load the log buffer pointer from the context, write it to the prog load attr struct.
		asm.LoadMem(asm.R1, ctxReg, progLogOff+offsetOf[signable.ProgramLog]("LogBuf"), asm.DWord).WithSource(asm.Comment("prog log ptr")),
		asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("LogBuf"), asm.R1, asm.DWord),
		asm.LoadMem(asm.R1, ctxReg, progLogOff+offsetOf[signable.ProgramLog]("LogSize"), asm.Word).WithSource(asm.Comment("prog log size")),
		asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("LogSize"), asm.R1, asm.Word),
		asm.LoadMem(asm.R1, ctxReg, progLogOff+offsetOf[signable.ProgramLog]("LogLevel"), asm.Word).WithSource(asm.Comment("prog log level")),
		asm.StoreMem(asm.R2, offsetOf[sys.ProgLoadAttrRaw]("LogLevel"), asm.R1, asm.Word),
		asm.Mov.Imm(asm.R1, int32(sys.BPF_PROG_LOAD)),
		asm.Mov.Imm(asm.R3, sizeOf[sys.ProgLoadAttrRaw]()),
		asm.FnSysBpf.Call(),
		// Copy the result into R7, in case we jump to the error case.
		asm.Mov.Reg(asm.R7, asm.R0),
		// Write the result into the context's FDs array at the allocated slot index.
		asm.StoreMem(ctxReg, offsetOf[signable.LoaderContext]("FDs")+int16(int32(progFDSlotIdx)*sizeOf[uint32]()), asm.R7, asm.Word),
		// Restore the map load attributes from the metadata map, so we can read values written to it by the kernel.
		asm.LoadMapValueIdx(asm.R2, metadataMapIdx, uint32(progAttrOff)).WithSource(asm.Comment("prog load attr ptr")),
		// Write the LogTrueSize reported by kernel to the context's ProgLogs array at the current program index.
		asm.LoadMem(asm.R1, asm.R2, offsetOf[sys.ProgLoadAttrRaw]("LogTrueSize"), asm.Word).WithSource(asm.Comment("log true size")),
		asm.StoreMem(ctxReg, progLogOff+offsetOf[signable.ProgramLog]("LogTrueSize"), asm.R1, asm.Word),
	)

	if !progBtfBuilder.Empty() {
		b.emit(
			// Close BTF file descriptor after load, don't need it anymore.
			asm.Mov.Reg(asm.R1, asm.R8),
			asm.FnSysClose.Call(),
		)
	}

	b.emit(
		// Check for error return, and just to error label if so.
		asm.JSLT.Imm(asm.R7, 0, "error"),
		// No-op to have a jump target.
		asm.Mov.Imm(asm.R0, 0).WithSymbol(skipLabel),
	)

	return nil
}

// associateMapIdx rewrites a map load to reference the map in the `idx` slot of the program's fdArray.
//
// A direct value load, which is how a program accesses a global variable in a .data, .rodata or .bss map, stays a
// value load at the same offset into the map value, as BPF_PSEUDO_MAP_IDX_VALUE. Instruction.AssociateMapIdx turns
// every map load into a map pointer load, BPF_PSEUDO_MAP_IDX, and drops the offset, which makes the verifier see a
// map_ptr where the program accesses the variable.
func associateMapIdx(ins *asm.Instruction, idx int) error {
	isValueLoad := ins.Src == asm.PseudoMapValue
	offset := uint32(uint64(ins.Constant) >> 32)

	if err := ins.AssociateMapIdx(idx); err != nil {
		return err
	}

	if isValueLoad {
		ins.Src = asm.PseudoMapIdxValue
		ins.Constant = int64(uint64(offset)<<32 | uint64(uint32(idx)))
	}

	return nil
}

func (b *builder) finalize() (*signable.Loader, error) {
	// If we reach this point, we have successful execution.
	b.emit(
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	)

	// If we jumped to the error label, we have failed execution.
	b.emit(
		asm.Mov.Imm(asm.R0, 1).WithSymbol("error"),
		asm.Return(),
	)

	btfBuilder, err := btf.NewBuilder(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create BTF builder: %w", err)
	}

	funcRefs := make(map[string]int)
	for _, f := range b.funcs {
		iter := f.insns.Iterate()
		for iter.Next() {
			if iter.Ins.IsFunctionCall() && iter.Ins.Reference() != "" {
				funcRefs[iter.Ins.Reference()]++
			}
		}
	}

	var insns asm.Instructions
	for i, f := range b.funcs {
		if len(f.insns) == 0 {
			continue
		}

		// Do not emit functions that are not referenced by any other function, except for the entrypoint function.
		if i > 0 && funcRefs[f.btf.Name] == 0 {
			continue
		}

		f.insns[0] = f.insns[0].WithSymbol(f.btf.Name)
		f.insns[0] = f.insns[0].WithSource(asm.Comment(f.btf.Name))
		f.insns[0] = btf.WithFuncMetadata(f.insns[0], f.btf)
		insns = append(insns, f.insns...)

		_, err = btfBuilder.Add(f.btf)
		if err != nil {
			return nil, fmt.Errorf("add BTF func %s: %w", f.btf.Name, err)
		}
	}

	if Debug {
		fmt.Printf("Loader instructions:\n")
		fmt.Println(insns)
	}

	var insnsBuf bytes.Buffer
	err = insns.Marshal(&insnsBuf, internal.NativeEndian)
	if err != nil {
		return nil, fmt.Errorf("marshal instructions: %w", err)
	}

	funcInfos, lineInfos, err := btf.MarshalExtInfos(insns, btfBuilder)
	if err != nil {
		return nil, fmt.Errorf("marshal ext_infos: %w", err)
	}

	slBTFBytes, err := btfBuilder.Marshal(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("marshal BTF: %w", err)
	}

	return &signable.Loader{
		Insns:          insnsBuf.Bytes(),
		Metadata:       b.metadata,
		FDSlots:        b.fdSlots,
		LoaderBTF:      slBTFBytes,
		LoaderFuncInfo: funcInfos,
		LoaderLineInfo: lineInfos,
	}, nil
}

// mdOffset holds the offset into the metadata
type mdOffset uint32

// addData appends the given data to the metadata and returns the offset at which it was added.
func (b *builder) addData(data []byte) (offset mdOffset) {
	offset = mdOffset(len(b.metadata))
	b.metadata = append(b.metadata, data...)
	return offset
}

// emit a list of instructions into the signable loader.
func (b *builder) emit(insns ...asm.Instruction) {
	b.funcs[0].emit(insns...)
}

// allocFDSlot allocates a slot in the loader context for a file descriptor, and returns the index of the slot.
func (b *builder) allocFDSlot(slot signable.FDSlot) (int, error) {
	if len(b.fdSlots) >= len(signable.LoaderContext{}.FDs) {
		return 0, fmt.Errorf("too many FD slots added to loader, max is %d", len(signable.LoaderContext{}.FDs))
	}
	b.fdSlots = append(b.fdSlots, slot)
	return len(b.fdSlots) - 1, nil
}

// offsetOf returns the offset of a field in a struct type T. It panics if the field does not exist.
func offsetOf[T any](field string) int16 {
	typ := reflect.TypeFor[T]()
	fld, found := typ.FieldByName(field)
	if !found {
		panic(fmt.Sprintf("field %s not found in type %s", field, typ.Name()))
	}
	return int16(fld.Offset)
}

// sizeOf returns the size of a struct type T in bytes.
func sizeOf[T any]() int32 {
	return int32(reflect.TypeFor[T]().Size())
}

type bpfFunc struct {
	btf   *btf.Func
	insns asm.Instructions
}

func (bf *bpfFunc) emit(insns ...asm.Instruction) {
	bf.insns = append(bf.insns, insns...)
}
