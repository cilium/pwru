package internal

import (
	"debug/elf"
	"fmt"
	"io"
)

type SafeELFFile struct {
	*elf.File
}

// NewSafeELFFile reads an ELF safely.
//
// Any panic during parsing is turned into an error. This is necessary since
// there are a bunch of unfixed bugs in debug/elf.
//
// https://github.com/golang/go/issues?q=is%3Aissue+is%3Aopen+debug%2Felf+in%3Atitle
func NewSafeELFFile(r io.ReaderAt) (safe *SafeELFFile, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		safe = nil
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	return &SafeELFFile{file}, nil
}

// SectionsByType returns all sections in the file with the specified section type.
func (se *SafeELFFile) SectionsByType(typ elf.SectionType) []*elf.Section {
	sections := make([]*elf.Section, 0, 1)
	for _, section := range se.Sections {
		if section.Type == typ {
			sections = append(sections, section)
		}
	}
	return sections
}
