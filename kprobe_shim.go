// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2022 Authors of Cilium */

package main

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
)

type Objs interface {
	GetKprobe(pos int) *ebpf.Program
	GetMap(name string) *ebpf.Map
	Close() error
}

func (o *KProbePWRUObjects) GetKprobe(pos int) *ebpf.Program {
	return getKprobe(o, pos)
}

func (o *KProbePWRUObjects) GetMap(name string) *ebpf.Map {
	return getMap(o, name)
}

func (o *KProbeMultiPWRUObjects) GetKprobe(pos int) *ebpf.Program {
	return getKprobe(o, pos)
}

func (o *KProbeMultiPWRUObjects) GetMap(name string) *ebpf.Map {
	return getMap(o, name)
}

func (o *KProbePWRUWithoutOutputSKBObjects) GetKprobe(pos int) *ebpf.Program {
	return getKprobe(o, pos)
}

func (o *KProbePWRUWithoutOutputSKBObjects) GetMap(name string) *ebpf.Map {
	return getMap(o, name)
}

func (o *KProbeMultiPWRUWithoutOutputSKBObjects) GetKprobe(pos int) *ebpf.Program {
	return getKprobe(o, pos)
}

func (o *KProbeMultiPWRUWithoutOutputSKBObjects) GetMap(name string) *ebpf.Map {
	return getMap(o, name)
}

func getKprobe(o Objs, pos int) *ebpf.Program {
	n := reflect.TypeOf(o).Elem().Name()
	field := reflect.ValueOf(o).Elem().FieldByName(strings.Replace(n, "Objects", "Programs", 1))
	prog := field.FieldByName(fmt.Sprintf("KprobeSkb%d", pos))

	return prog.Interface().(*ebpf.Program)
}

func getMap(o Objs, name string) *ebpf.Map {
	n := reflect.TypeOf(o).Elem().Name()
	field := reflect.ValueOf(o).Elem().FieldByName(strings.Replace(n, "Objects", "Maps", 1))
	prog := field.FieldByName(name)

	return prog.Interface().(*ebpf.Map)
}
