package cbpfc

import (
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

const funcTemplate = `
// True if packet matches, false otherwise
{{- if not .NoInline}}
__attribute__((__always_inline__)) static inline
{{- end}}
uint32_t {{.Name}}(const uint8_t *const data, const uint8_t *const data_end) {
	__attribute__((unused))
	uint32_t a, x, m[16];
	__attribute__((unused))
	const uint8_t *indirect;

{{range $i, $b := .Blocks}}
{{$b.Label}}:
__attribute__((unused));
{{- range $i, $s := $b.Statements}}
	{{$s}}
{{- end}}
{{end}}
}`

type cFunction struct {
	Name     string
	NoInline bool
	Blocks   []cBlock
}

// cBPF reg to C symbol
var regToCSym = map[bpf.Register]string{
	bpf.RegA: "a",
	bpf.RegX: "x",
}

// alu operation to C operator
var aluToCOp = map[bpf.ALUOp]string{
	bpf.ALUOpAdd:        "+",
	bpf.ALUOpSub:        "-",
	bpf.ALUOpMul:        "*",
	bpf.ALUOpDiv:        "/",
	bpf.ALUOpOr:         "|",
	bpf.ALUOpAnd:        "&",
	bpf.ALUOpShiftLeft:  "<<",
	bpf.ALUOpShiftRight: ">>",
	bpf.ALUOpMod:        "%",
	bpf.ALUOpXor:        "^",
}

// jump test to a C fmt string for condition
var condToCFmt = map[bpf.JumpTest]string{
	bpf.JumpEqual:          "a == %v",
	bpf.JumpNotEqual:       "a != %v",
	bpf.JumpGreaterThan:    "a > %v",
	bpf.JumpLessThan:       "a < %v",
	bpf.JumpGreaterOrEqual: "a >= %v",
	bpf.JumpLessOrEqual:    "a <= %v",
	bpf.JumpBitsSet:        "a & %v",
	bpf.JumpBitsNotSet:     "!(a & %v)",
}

var funcNameRegex = regexp.MustCompile(`^[A-Za-z_][0-9A-Za-z_]*$`)

// cBLock is a block of compiled C
type cBlock struct {
	*block

	Statements []string
}

type COpts struct {
	// FunctionName is the symbol to use as the generated C function. Must match regex:
	//     [A-Za-z_][0-9A-Za-z_]*
	FunctionName string

	// NoInline doesn't force the generated function to be inlined, allowing clang to emit
	// a BPF to BPF call.
	// Requires at least kernel 5.10 (for x86, later for other architectures) if used with tail-calls.
	NoInline bool
}

// ToC compiles a cBPF filter to a C function with a signature of:
//
//	uint32_t opts.FunctionName(const uint8_t *const data, const uint8_t *const data_end)
//
// The function returns the filter's return value:
// 0 if the packet does not match the cBPF filter,
// non 0 if the packet does match.
func ToC(filter []bpf.Instruction, opts COpts) (string, error) {
	if !funcNameRegex.MatchString(opts.FunctionName) {
		return "", errors.Errorf("invalid FunctionName %q", opts.FunctionName)
	}

	blocks, err := compile(filter)
	if err != nil {
		return "", err
	}

	fun := cFunction{
		Name:   opts.FunctionName,
		Blocks: make([]cBlock, len(blocks)),
	}

	// Compile blocks to C
	for i, block := range blocks {
		fun.Blocks[i], err = blockToC(block)
		if err != nil {
			return "", err
		}
	}

	// Fill in the template
	tmpl, err := template.New("cbfp_func").Parse(funcTemplate)
	if err != nil {
		return "", errors.Wrapf(err, "unable to parse func template")
	}

	c := strings.Builder{}

	if err := tmpl.Execute(&c, fun); err != nil {
		return "", errors.Wrapf(err, "unable to execute func template")
	}

	return c.String(), nil
}

// blockToC compiles a block to C.
func blockToC(blk *block) (cBlock, error) {
	cBlk := cBlock{
		block: blk,
	}

	for _, insn := range blk.insns {
		stat, err := insnToC(insn, blk)
		if err != nil {
			return cBlk, errors.Wrapf(err, "unable to compile %v", insn)
		}

		cBlk.Statements = append(cBlk.Statements, stat...)
	}

	return cBlk, nil
}

// insnToC compiles an instruction to a single C line / statement.
func insnToC(insn instruction, blk *block) ([]string, error) {
	switch i := insn.Instruction.(type) {

	case bpf.LoadConstant:
		return stat("%s = %d;", regToCSym[i.Dst], i.Val)
	case bpf.LoadScratch:
		return stat("%s = m[%d];", regToCSym[i.Dst], i.N)
	case bpf.LoadAbsolute:
		return packetLoadToC(i.Size, "data + %d", i.Off)
	case bpf.LoadIndirect:
		return packetLoadToC(i.Size, "indirect + %d", i.Off)
	case bpf.LoadMemShift:
		return stat("x = 4*(*(data + %d) & 0xf);", i.Off)

	case bpf.StoreScratch:
		return stat("m[%d] = %s;", i.N, regToCSym[i.Src])

	case bpf.LoadExtension:
		if i.Num != bpf.ExtLen {
			return nil, errors.Errorf("unsupported BPF extension %v", i)
		}

		return stat("a = data_end - data;")

	case bpf.ALUOpConstant:
		return stat("a %s= %d;", aluToCOp[i.Op], i.Val)
	case bpf.ALUOpX:
		return stat("a %s= x;", aluToCOp[i.Op])
	case bpf.NegateA:
		return stat("a = -a;")

	case bpf.Jump:
		return stat("goto %s;", blk.skipToBlock(skip(i.Skip)).Label())
	case bpf.JumpIf:
		return condToC(skip(i.SkipTrue), skip(i.SkipFalse), blk, condToCFmt[i.Cond], i.Val)
	case bpf.JumpIfX:
		return condToC(skip(i.SkipTrue), skip(i.SkipFalse), blk, condToCFmt[i.Cond], "x")

	case bpf.RetA:
		return stat("return a;")
	case bpf.RetConstant:
		return stat("return %d;", i.Val)

	case bpf.TXA:
		return stat("a = x;")
	case bpf.TAX:
		return stat("x = a;")

	case packetGuardAbsolute:
		return stat("if (data + %d > data_end) return 0;", i.end)
	case packetGuardIndirect:
		return []string{
			// Sign extend RegX to 64bits.
			fmt.Sprintf("indirect = (uint8_t *) (((int64_t) (int32_t) x) + %d);", i.start),
			fmt.Sprintf("if ((uint64_t)indirect >= %d) return false;", i.maxStartOffset()),
			fmt.Sprintf("indirect = data + (uint64_t)indirect;"),
			// Prevent clang from calculating indirect + delta() directly from the packet start when RegX is constant:
			// only indirect has the correct bounds check.
			fmt.Sprintf(`asm volatile("" : : "r" (indirect));`),
			fmt.Sprintf("if (indirect + %d > data_end) return false;", i.length()),
		}, nil

	case checkXNotZero:
		return stat("if (x == 0) return 0;")

	default:
		return nil, errors.Errorf("unsupported instruction %v", insn)
	}
}

func packetLoadToC(size int, offsetFmt string, offsetArgs ...interface{}) ([]string, error) {
	offset := fmt.Sprintf(offsetFmt, offsetArgs...)

	switch size {
	case 1:
		return stat("a = *(%s);", offset)
	case 2:
		return stat("a = ntohs(*((uint16_t *) (%s)));", offset)
	case 4:
		return stat("a = ntohl(*((uint32_t *) (%s)));", offset)
	}

	return nil, errors.Errorf("unsupported load size %d", size)
}

func condToC(skipTrue, skipFalse skip, blk *block, condFmt string, condArgs ...interface{}) ([]string, error) {
	cond := fmt.Sprintf(condFmt, condArgs...)

	if skipFalse == 0 {
		return stat("if (%s) goto %s;", cond, blk.skipToBlock(skipTrue).Label())
	}

	return stat("if (%s) goto %s; else goto %s;", cond, blk.skipToBlock(skipTrue).Label(), blk.skipToBlock(skipFalse).Label())
}

func stat(format string, a ...interface{}) ([]string, error) {
	return []string{fmt.Sprintf(format, a...)}, nil
}
