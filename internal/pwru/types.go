package pwru

const (
	CFG_FILTER_KEY_MARK     = 0x0
	CFG_FILTER_KEY_PROTO    = 0x1
	CFG_FILTER_KEY_SRC_IP   = 0x2
	CFG_FILTER_KEY_DST_IP   = 0x3
	CFG_FILTER_KEY_SRC_PORT = 0x4
	CFG_FILTER_KEY_DST_PORT = 0x5
	CFG_OUTPUT_META         = 0x6
	CFG_OUTPUT_TUPLE        = 0x7
	CFG_OUTPUT_SKB          = 0x8
)

type Flags struct {
	FilterMark    *int
	FilterProto   *string
	FilterSrcIP   *string
	FilterDstIP   *string
	FilterSrcPort *string
	FilterDstPort *string

	OutputRelativeTS *bool
	OutputMeta       *bool
	OutputTuple      *bool
	OutputSkb        *bool
}

type Tuple struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
	Proto uint8
	Pad   [7]uint8
}

type Meta struct {
	Mark    uint32
	Ifindex uint32
	Len     uint32
	MTU     uint32
	Proto   uint16
	Pad     uint16
}

type Event struct {
	PID        uint32
	Type       uint32
	Addr       uint64
	SAddr      uint64
	Timestamp  uint64
	PrintSkbId uint64
	Meta       Meta
	Tuple      Tuple
}
