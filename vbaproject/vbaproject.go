package vbaproject

import (
	"github.com/coffeeforyou/vbasig/vbaproject/dirstream"
	"github.com/coffeeforyou/vbasig/vbaproject/modulestream"
	"github.com/coffeeforyou/vbasig/vbaproject/projectstream"
)

type VbaProject struct {
	DirStream     *dirstream.DirStream
	ProjectStream projectstream.ProjectStream
	ModuleStream  modulestream.ModuleStream
}

type ModuleWithOffset struct {
	Name   string
	Offset uint32 // byte offset of the source code in the ModuleStream
}

func (p *VbaProject) GetModulesWithOffset() []ModuleWithOffset {
	mswo := []ModuleWithOffset{}
	for _, m := range p.DirStream.ModulesRecord.Modules {
		tmp := ModuleWithOffset{}
		tmp.Name = string(m.NameRecord.ModuleName)
		tmp.Offset = m.OffsetRecord.TextOffset
		mswo = append(mswo, tmp)
	}
	return mswo
}
