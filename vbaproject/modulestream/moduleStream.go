package modulestream

import "github.com/coffeeforyou/vbasig/vbacompression"

// MODULE Record
type ModuleStream struct {
	Modules []*Module
}

type Module struct {
	Name                 string
	CompressedSourceCode []byte
	SourceCode           []byte
	ChildStreams         []ChildStream
	Raw                  []byte
}

type ChildStream struct {
	Name string
	Path []string
	Raw  []byte
}

func ParseModuleStream(moduleStreamBytes []byte) (*Module, error) {
	tmp := Module{}
	var err error
	tmp.CompressedSourceCode = moduleStreamBytes
	tmp.SourceCode, _, err = vbacompression.DecompressContainer(moduleStreamBytes)
	if err != nil {
		return nil, err
	}
	return &tmp, nil
}

func (ms *ModuleStream) GetModule(name string) *Module {
	for _, m := range ms.Modules {
		if m.Name == name {
			return m
		}
	}
	return nil
}
