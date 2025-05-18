package dirstream

import (
	"bytes"
)

// DIR STREAM Record
type DirStream struct {
	InformationRecord *ProjectInformation // PROJECTINFORMATION Record (variable length)
	ReferencesRecord  *ProjectReferences  // PROJECTREFERENCES Record (variable length)
	ModulesRecord     *ProjectModules     // PROJECTMODULES Record (variable length)
	Terminator        uint16              // MUST be 0x0010
	Reserved          uint32              // MUST be 0x00000000, ignored
}

func ParseDirStream(reader *bytes.Reader) (*DirStream, error) {
	var ds DirStream
	var err error
	ds.InformationRecord, err = ParseProjectInfo(reader)
	if err != nil {
		return nil, err
	}
	ds.ReferencesRecord, err = ParseProjectReferences(reader, ds.InformationRecord)
	if err != nil {
		return nil, err
	}
	ds.ModulesRecord, err = ParseProjectModules(reader, ds.InformationRecord)
	if err != nil {
		return nil, err
	}
	return &ds, nil
}
