package signable

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf-sl/internal"
	"github.com/cilium/ebpf-sl/internal/crypto/pkcs7"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/sys"
	"golang.org/x/sys/unix"
)

type Loader struct {
	// Generated from the builder.
	Insns          []byte
	Metadata       []byte
	FDSlots        []FDSlot
	LoaderBTF      []byte
	LoaderFuncInfo []byte
	LoaderLineInfo []byte

	// Generated while signing.
	Signature []byte

	// Populated during [Loader.Load]
	LoaderLog string
}

// FDSlot describes how a given slot in [LoaderContext.FDs] is used.
type FDSlot struct {
	Map  *string
	Prog *string
}

type SignOptions struct {
	// The hash function used to hash the instructions before signing.
	// Defaults to SHA3_256 if not specified.
	Hash crypto.Hash
	// The certificate used to sign the content. This must be a valid X.509 certificate.
	Certificate *x509.Certificate
	// The private key used to sign the content. This must correspond to the public key in the certificate.
	PrivateKey crypto.PrivateKey
}

func (l *Loader) Sign(opts SignOptions) error {
	payload := append(l.Insns, l.Metadata...)
	signature, err := pkcs7.Sign(payload, pkcs7.SignOptions{
		Hash:        opts.Hash,
		Certificate: opts.Certificate,
		PrivateKey:  opts.PrivateKey,
	})
	if err != nil {
		return fmt.Errorf("sign loader: %w", err)
	}

	l.Signature = signature
	return nil
}

type LoaderOptions struct {
	// The ID of the kernel keyring to which the certificate used for signing is added.
	KeyringID int32

	LoaderLogLevel     ebpf.LogLevel
	LoaderLogSizeStart uint32

	LogLevel     ebpf.LogLevel
	LogSizeStart uint32
}

// LoaderContext is the context passed to the signed loader program, it acts both as inputs
// and outputs for the signed loader program.
type LoaderContext struct {
	FDs      [128]int32
	ProgLogs [64]ProgramLog
}

type ProgramLog struct {
	// Pointer to the log buffer in userspace.
	LogBuf uint64
	// LogLevel the verbosity level of the log buffer.
	LogLevel ebpf.LogLevel
	// LogSize the size of the log buffer in userspace.
	LogSize uint32
	// LogTrueSize the true size of the log buffer as reported by the kernel.
	LogTrueSize uint32
	_           [4]byte // Padding to align to 8 bytes.
}

func (l *Loader) Load(opts *LoaderOptions) (*ebpf.Collection, error) {
	fd, err := l.loadLoader(opts)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = fd.Close()
	}()

	coll, err := l.loadCollection(fd, LoaderContext{}, opts)
	if err != nil {
		return nil, fmt.Errorf("load collection: %w", err)
	}

	return coll, nil
}

func (l *Loader) LoadAndAssign(to any, opts *LoaderOptions) error {
	fd, err := l.loadLoader(opts)
	if err != nil {
		return err
	}
	defer func() {
		_ = fd.Close()
	}()

	if err := internal.IsNilPointer(to); err != nil {
		return err
	}

	toValue := reflect.ValueOf(to)
	if toValue.Type().Kind() != reflect.Pointer {
		return fmt.Errorf("%T is not a pointer to struct", to)
	}

	fields, err := ebpfFields(toValue.Elem(), nil)
	if err != nil {
		return err
	}

	// Find the FDs of programs not referenced by the struct, and set placeholder FDs to prevent the signed loader
	// from creating them.
	ctx := LoaderContext{}
	for i, slot := range l.FDSlots {
		if slot.Prog != nil {
			idx := slices.IndexFunc(fields, func(field structField) bool {
				return reflect.TypeFor[*ebpf.Program]() == field.Type && field.Tag.Get("ebpf") == *slot.Prog
			})
			if idx == -1 {
				ctx.FDs[i] = fdPlaceholder
			}
		}
	}

	coll, err := l.loadCollection(fd, ctx, opts)
	if err != nil {
		return fmt.Errorf("load collection: %w", err)
	}

	for _, field := range fields {
		var value any
		switch field.Type {
		case reflect.TypeFor[*ebpf.Map]():
			m, ok := coll.Maps[field.Tag.Get("ebpf")]
			if !ok {
				return fmt.Errorf("map %q not found in collection", field.Tag.Get("ebpf"))
			}
			value = m
		case reflect.TypeFor[*ebpf.Program]():
			p, ok := coll.Programs[field.Tag.Get("ebpf")]
			if !ok {
				return fmt.Errorf("program %q not found in collection", field.Tag.Get("ebpf"))
			}
			value = p
		default:
			return fmt.Errorf("unsupported field type %s for field %s", field.Type, field.Name)
		}
		field.value.Set(reflect.ValueOf(value))
	}

	return nil
}

// structField represents a struct field containing the ebpf struct tag.
type structField struct {
	reflect.StructField
	value reflect.Value
}

// ebpfFields extracts field names tagged with 'ebpf' from a struct type.
// Keep track of visited types to avoid infinite recursion.
func ebpfFields(structVal reflect.Value, visited map[reflect.Type]bool) ([]structField, error) {
	if visited == nil {
		visited = make(map[reflect.Type]bool)
	}

	structType := structVal.Type()
	if structType.Kind() != reflect.Struct {
		return nil, fmt.Errorf("%s is not a struct", structType)
	}

	if visited[structType] {
		return nil, fmt.Errorf("recursion on type %s", structType)
	}

	fields := make([]structField, 0, structType.NumField())
	for i := 0; i < structType.NumField(); i++ {
		field := structField{structType.Field(i), structVal.Field(i)}

		// If the field is tagged, gather it and move on.
		name := field.Tag.Get("ebpf")
		if strings.Contains(name, ",") {
			return nil, fmt.Errorf("field %s: ebpf tag contains a comma", field.Name)
		}
		if name != "" {
			fields = append(fields, field)
			continue
		}

		// If the field does not have an ebpf tag, but is a struct or a pointer
		// to a struct, attempt to gather its fields as well.
		var v reflect.Value
		switch field.Type.Kind() {
		case reflect.Pointer:
			if field.Type.Elem().Kind() != reflect.Struct {
				continue
			}

			if field.value.IsNil() {
				return nil, fmt.Errorf("nil pointer to %s", structType)
			}

			// Obtain the destination type of the pointer.
			v = field.value.Elem()

		case reflect.Struct:
			// Reference the value's type directly.
			v = field.value

		default:
			continue
		}

		inner, err := ebpfFields(v, visited)
		if err != nil {
			return nil, fmt.Errorf("field %s: %w", field.Name, err)
		}

		fields = append(fields, inner...)
	}

	return fields, nil
}

func (l *Loader) loadLoader(opts *LoaderOptions) (*sys.FD, error) {
	if len(l.Metadata) == 0 {
		return nil, fmt.Errorf("no metadata provided, trying to load empty collection?")
	}

	mapAttr := &sys.MapCreateAttr{
		MapName:    internal.MaybeFillObjName("ebpfgo_sl_md"),
		MapType:    sys.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  uint32(len(l.Metadata)),
		MaxEntries: 1,
	}

	// Only set the exclusive program hash if a signature is present.
	// Program hash calculation is different when no signature is present, and having a exclusive map is not required
	// for unsigned programs.
	if len(l.Signature) > 0 {
		h := sha256.New()
		h.Write(l.Insns)
		progHash := h.Sum(nil)

		mapAttr.ExclProgHash = sys.SlicePointer(progHash)
		mapAttr.ExclProgHashSize = uint32(len(progHash))
	}

	metadataMapFD, err := sys.MapCreate(mapAttr)
	if err != nil {
		return nil, fmt.Errorf("create metadata map: %w", err)
	}

	metadataMap, err := ebpf.NewMapFromFD(metadataMapFD.Int())
	if err != nil {
		return nil, fmt.Errorf("create metadata map from FD: %w", err)
	}
	defer func() {
		_ = metadataMap.Close()
	}()

	if err := metadataMap.Put(uint32(0), l.Metadata); err != nil {
		return nil, fmt.Errorf("write metadata to map: %w", err)
	}

	if err := metadataMap.Freeze(); err != nil {
		return nil, fmt.Errorf("freeze metadata map: %w", err)
	}

	loaderBtfFD, err := sys.BtfLoad(&sys.BtfLoadAttr{
		Btf:     sys.SlicePointer(l.LoaderBTF),
		BtfSize: uint32(len(l.LoaderBTF)),
	})
	if err != nil {
		return nil, fmt.Errorf("load loader BTF: %w", err)
	}

	fdArray := []int32{
		// Metadata map at index 0, as per signed loader external contract.
		int32(metadataMap.FD()),
	}

	attr := &sys.ProgLoadAttr{
		ProgName:        internal.MaybeFillObjName("ebpfgo_sl"),
		ProgType:        sys.ProgType(ebpf.Syscall),
		ProgFlags:       unix.BPF_F_SLEEPABLE,
		License:         sys.NewStringPointer("Dual MIT/GPL"),
		Insns:           sys.SlicePointer(l.Insns),
		InsnCnt:         uint32(len(l.Insns) / asm.InstructionSize),
		FdArray:         sys.SlicePointer(fdArray),
		FdArrayCnt:      uint32(len(fdArray)),
		ProgBtfFd:       loaderBtfFD.Uint(),
		FuncInfo:        sys.SlicePointer(l.LoaderFuncInfo),
		FuncInfoRecSize: btf.FuncInfoSize,
		FuncInfoCnt:     uint32(len(l.LoaderFuncInfo) / int(btf.FuncInfoSize)),
		LineInfo:        sys.SlicePointer(l.LoaderLineInfo),
		LineInfoRecSize: btf.LineInfoSize,
		LineInfoCnt:     uint32(len(l.LoaderLineInfo) / int(btf.LineInfoSize)),
	}

	if len(l.Signature) > 0 {
		attr.Signature = sys.SlicePointer(l.Signature)
		attr.SignatureSize = uint32(len(l.Signature))
		attr.KeyringId = opts.KeyringID
	}

	var (
		logBuf []byte
		fd     *sys.FD
	)

	// Only specify log size if log level is also specified. Setting size
	// without level results in EINVAL. Level will be bumped to LogLevelBranch
	// if the first load fails.
	if opts.LoaderLogLevel != 0 {
		attr.LogLevel = opts.LoaderLogLevel
		attr.LogSize = internal.Between(opts.LoaderLogSizeStart, minVerifierLogSize, maxVerifierLogSize)
	}

	attempts := 1
	for {
		if attr.LogLevel != 0 {
			logBuf = make([]byte, attr.LogSize)
			attr.LogBuf = sys.SlicePointer(logBuf)
		}

		fd, err = sys.ProgLoad(attr)
		if err == nil {
			end := bytes.IndexByte(logBuf, 0)
			if end == -1 {
				end = len(logBuf)
			}
			l.LoaderLog = string(logBuf[:end])
			return fd, nil
		}

		if !retryLoadLogAttrs(&attr.LogLevel, &attr.LogSize, &attr.LogTrueSize, opts.LoaderLogSizeStart, err) {
			break
		}

		if attempts >= maxVerifierAttempts {
			return nil, fmt.Errorf("load program: %w (bug: hit %d verifier attempts)", err, maxVerifierAttempts)
		}
		attempts++
	}

	return nil, programLoadError(err, logBuf)
}

// File descriptor 1 is stdin, and thus will never be a valid new file descriptor returned by the kernel.
// We use it as a placeholder, the signed loader will see a positive non-zero value and skip creation.
var fdPlaceholder int32 = 1

func (l *Loader) loadCollection(slFD *sys.FD, ctx LoaderContext, opts *LoaderOptions) (*ebpf.Collection, error) {
	// Do initial setup of program logs in the context.
	progIdx := 0
	programLogs := make([][]byte, 0)
	for _, slot := range l.FDSlots {
		if slot.Prog == nil {
			continue
		}

		progLog := ProgramLog{
			LogLevel: opts.LogLevel,
			LogSize:  internal.Between(opts.LogSizeStart, minVerifierLogSize, maxVerifierLogSize),
		}
		if progLog.LogLevel == 0 {
			progLog.LogSize = 0
		}
		ctx.ProgLogs[progIdx] = progLog
		programLogs = append(programLogs, nil)
		progIdx++
	}

	attempts := 1
retry:
	for {
		progIdx := 0
		for _, slot := range l.FDSlots {
			if slot.Prog == nil {
				continue
			}

			// If the actual size of the log buffer does not match the desired size, reallocate the buffer and update the pointer in the context.
			if len(programLogs[progIdx]) != int(ctx.ProgLogs[progIdx].LogSize) {
				programLogs[progIdx] = make([]byte, ctx.ProgLogs[progIdx].LogSize)
				ctx.ProgLogs[progIdx].LogBuf = uint64(uintptr(unsafe.Pointer(&programLogs[progIdx][0])))
			}

			progIdx++
		}

		ctxBytes, err := binary.Append(nil, internal.NativeEndian, ctx)
		if err != nil {
			return nil, fmt.Errorf("marshal loader context: %w", err)
		}

		progRunAttr := &sys.ProgRunAttr{
			ProgFd:    slFD.Uint(),
			CtxIn:     sys.SlicePointer(ctxBytes),
			CtxSizeIn: uint32(len(ctxBytes)),
		}

		err = sys.ProgRun(progRunAttr)
		if err != nil {
			return nil, fmt.Errorf("signed loader prog run: %w", err)
		}

		_, err = binary.Decode(ctxBytes, internal.NativeEndian, &ctx)
		if err != nil {
			return nil, fmt.Errorf("unmarshal loader context: %w", err)
		}

		coll := &ebpf.Collection{
			Maps:     make(map[string]*ebpf.Map),
			Programs: make(map[string]*ebpf.Program),
		}

		// Do error checking, see if we need to retry/resume collection loading.
		progIdx = 0
		for i, slot := range l.FDSlots {
			fd := ctx.FDs[i]

			if slot.Map != nil {
				if fd >= 0 {
					continue
				}
				return nil, fmt.Errorf("create map %q error: %w", *slot.Map, unix.Errno(-fd))
			} else if slot.Prog != nil {
				// A negative FD indicates an error occurred while loading the program.
				if fd >= 0 {
					progIdx++
					continue
				}

				err = unix.Errno(-fd)
				// See if this is an error we should retry with a logging enabled or larger log buffer.
				if !retryLoadLogAttrs(&ctx.ProgLogs[progIdx].LogLevel, &ctx.ProgLogs[progIdx].LogSize, &ctx.ProgLogs[progIdx].LogTrueSize, opts.LoaderLogSizeStart, err) {
					return nil, internal.ErrorWithLog("program "+*slot.Prog, err, programLogs[progIdx])
				}

				if attempts >= maxVerifierAttempts {
					return nil, fmt.Errorf("load program: %w (bug: hit %d verifier attempts)", err, maxVerifierAttempts)
				}
				attempts++
				continue retry
			} else {
				return nil, fmt.Errorf("loader context FD slot %d has no associated map or program", i)
			}
		}

		// If we did not find an error in the fd slots, but the signed loader returned a non-zero retval anyway.
		// Should not happen, but if it does, return an error.
		if progRunAttr.Retval != 0 {
			return nil, fmt.Errorf("signed loader prog run error: %d", progRunAttr.Retval)
		}

		// Convert the FDs to maps and programs, and add them to the collection.
		progIdx = 0
		for i, slot := range l.FDSlots {
			fd := ctx.FDs[i]

			if slot.Map != nil {
				// If a map fd is 0, it means the signed loader skipped creation of the map, most likely because it
				// was never referenced by a program we are loading.
				if fd == 0 {
					continue
				}

				m, err := ebpf.NewMapFromFD(int(fd))
				if err != nil {
					return nil, fmt.Errorf("create map %s from FD: %w", *slot.Map, err)
				}
				coll.Maps[*slot.Map] = m
			} else if slot.Prog != nil {
				// If a program fd is the placeholder value, then we intentionally skipped creation of the program.
				if fd == fdPlaceholder {
					continue
				}

				p, err := ebpf.NewProgramFromFD(int(fd))
				if err != nil {
					return nil, fmt.Errorf("create program %s from FD: %w", *slot.Prog, err)
				}

				p.VerifierLog = unix.ByteSliceToString(programLogs[progIdx])
				coll.Programs[*slot.Prog] = p
				progIdx++
			} else {
				return nil, fmt.Errorf("loader context FD slot %d has no associated map or program", i)
			}
		}

		return coll, nil
	}
}

func programLoadError(err error, logBuf []byte) error {
	switch {
	// TODO (dylandreimerink): Probe for signing support and return a sentinel error if not supported.
	case errors.Is(err, unix.EOPNOTSUPP):
		return fmt.Errorf("signed loader: %w (signing possibly not supported, was kernel compiled with CONFIG_SYSTEM_DATA_VERIFICATION?)", err)

		// TODO (dylandreimerink): Probe for signing support and return a sentinel error if not supported.
	case errors.Is(err, unix.E2BIG):
		return fmt.Errorf("signed loader: %w (no signature support, kernel version possibly below 6.18)", err)

	case errors.Is(err, unix.ENOKEY):
		return fmt.Errorf("signed loader: %w (no cert found for signature in keyring)", err)

	case errors.Is(err, unix.EFAULT):
		// EFAULT is returned when the kernel hits a verifier bug, and always
		// overrides ENOSPC, defeating the buffer growth strategy. Warn the user
		// that they may need to increase the buffer size manually. Preserve the
		// verifier log when it contains the actual rejection reason.
		return fmt.Errorf("signed loader: %w (increase LogSizeStart to fit the log and check dmesg)",
			internal.ErrorWithLog("hit verifier bug", err, logBuf))
	}

	return internal.ErrorWithLog("signed loader", err, logBuf)
}

// minVerifierLogSize is the default number of bytes allocated for the
// verifier log.
const minVerifierLogSize = 64 * 1024

// maxVerifierLogSize is the maximum size of verifier log buffer the kernel
// will accept before returning EINVAL. May be increased to MaxUint32 in the
// future, but avoid the unnecessary EINVAL for now.
const maxVerifierLogSize = math.MaxUint32 >> 2

// maxVerifierAttempts is the maximum number of times the verifier will retry
// loading a program with a growing log buffer before giving up. Since we double
// the log size on every attempt, this is the absolute maximum number of
// attempts before the buffer reaches [maxVerifierLogSize].
const maxVerifierAttempts = 30

func retryLoadLogAttrs(logLevel *ebpf.LogLevel, logSize *uint32, logTrueSize *uint32, startSize uint32, err error) bool {
	if *logSize == maxVerifierLogSize {
		// Maximum buffer size reached, don't grow or retry.
		return false
	}

	// ENOSPC means the log was enabled on the previous iteration, so we only
	// need to grow the buffer.
	if errors.Is(err, unix.ENOSPC) {
		if *logTrueSize != 0 {
			// Kernel supports LogTrueSize and previous iteration undershot the buffer
			// size. Try again with the given true size.
			*logSize = *logTrueSize
			return true
		}

		// Ensure the size doesn't overflow.
		const factor = 2
		if *logSize >= maxVerifierLogSize/factor {
			*logSize = maxVerifierLogSize
			return true
		}

		// Make an educated guess how large the buffer should be by multiplying. Due
		// to int division, this rounds down odd sizes.
		*logSize = internal.Between(*logSize, minVerifierLogSize, maxVerifierLogSize/factor)
		*logSize *= factor

		return true
	}

	if *logLevel == 0 {
		// Loading the program failed, it wasn't a buffer-related error, and the log
		// was disabled the previous iteration. Enable basic logging and retry.
		*logLevel = ebpf.LogLevelBranch
		*logSize = internal.Between(startSize, minVerifierLogSize, maxVerifierLogSize)
		return true
	}

	// Loading the program failed for a reason other than buffer size and the log
	// was already enabled the previous iteration. Don't retry.
	return false
}
