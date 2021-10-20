package pwru

import "testing"

func TestAddr2Name_findNearestSym(t *testing.T) {
	type fields struct {
		Addr2NameMap   map[uint64]*ksym
		Addr2NameSlice []*ksym
	}
	type args struct {
		ip uint64
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "Correctly find the symbol in the middle",
			fields: fields{
				Addr2NameMap: nil,
				Addr2NameSlice: []*ksym{
					&ksym{
						addr: 0x00001,
						name: "test1",
					},
					&ksym{
						addr: 0x11111,
						name: "test2",
					},
				},
			},
			args: args{ip: 0x00010},
			want: "test1",
		},
		{
			name: "Correctly find symbol that are outside the boundary",
			fields: fields{
				Addr2NameMap: nil,
				Addr2NameSlice: []*ksym{
					&ksym{
						addr: 0x00001,
						name: "test1",
					},
					&ksym{
						addr: 0x11111,
						name: "test2",
					},
				},
			},
			args: args{ip: 0x22222},
			want: "test2",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Addr2Name{
				Addr2NameMap:   tt.fields.Addr2NameMap,
				Addr2NameSlice: tt.fields.Addr2NameSlice,
			}
			if got := a.findNearestSym(tt.args.ip); got != tt.want {
				t.Errorf("findNearestSym() = %v, want %v", got, tt.want)
			}
		})
	}
}
