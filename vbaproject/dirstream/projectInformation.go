package dirstream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// Define struct for each record as per the specification
type ProjectInformation struct {
	SysKind       ProjectSysKind
	CompatVersion ProjectCompatVersion
	Lcid          ProjectLcid
	LcidInvoke    ProjectLcidInvoke
	CodePage      ProjectCodePage
	Name          ProjectName
	DocString     ProjectDocString
	HelpFilePath  ProjectHelpFilePath
	HelpContext   ProjectHelpContext
	LibFlags      ProjectLibFlags
	Version       ProjectVersion
	Constants     ProjectConstants
}

// PROJECTSYSKIND Record
type ProjectSysKind struct {
	Size    uint32
	SysKind uint32
}

// PROJECTCOMPATVERSION Record
type ProjectCompatVersion struct {
	Size          uint32
	CompatVersion uint32
}

// PROJECTLCID Record
type ProjectLcid struct {
	Size uint32
	Lcid uint32
}

// PROJECTLCIDINVOKE Record
type ProjectLcidInvoke struct {
	Size       uint32
	LcidInvoke uint32
}

// PROJECTCODEPAGE Record
type ProjectCodePage struct {
	Size     uint32
	CodePage uint16
}

// PROJECTNAME Record (Variable Length)
type ProjectName struct {
	SizeOfProjectName uint32
	ProjectName       []byte
}

// PROJECTDOCSTRING Record (Variable Length)
type ProjectDocString struct {
	SizeOfDocString        uint32
	DocString              []byte
	Reserved               uint16
	SizeOfDocStringUnicode uint32
	DocStringUnicode       string
}

// PROJECTHELPFILEPATH Record (Variable Length)
type ProjectHelpFilePath struct {
	SizeOfHelpFile1 uint32
	HelpFile1       []byte
	Reserved        uint16
	SizeOfHelpFile2 uint32
	HelpFile2       []byte
}

// PROJECTHELPCONTEXT Record
type ProjectHelpContext struct {
	Size        uint32
	HelpContext uint32
}

// PROJECTLIBFLAGS Record
type ProjectLibFlags struct {
	Size            uint32
	ProjectLibFlags uint32
}

// PROJECTVERSION Record
type ProjectVersion struct {
	Reserved     uint32
	VersionMajor uint32
	VersionMinor uint16
}

// PROJECTCONSTANTS Record (Variable Length)
type ProjectConstants struct {
	SizeOfConstants        uint32
	Constants              []byte
	Reserved               uint16
	SizeOfConstantsUnicode uint32
	ConstantsUnicode       []byte
}

// Parse the binary data
func ParseProjectInfo(reader *bytes.Reader) (*ProjectInformation, error) {
	var pi ProjectInformation

	// Read and parse records depending on record id
	var nid uint16
	for {
		err := binary.Read(reader, binary.LittleEndian, &nid)
		if err != nil {
			return nil, fmt.Errorf("failed to read id (record): %w", err)
		}
		switch nid {
		case 0x0001:
			err = binary.Read(reader, binary.LittleEndian, &pi.SysKind)
		case 0x004a:
			err = binary.Read(reader, binary.LittleEndian, &pi.CompatVersion)
		case 0x0002:
			err = binary.Read(reader, binary.LittleEndian, &pi.Lcid)
		case 0x0014:
			err = binary.Read(reader, binary.LittleEndian, &pi.LcidInvoke)
		case 0x0003:
			err = binary.Read(reader, binary.LittleEndian, &pi.CodePage)
		case 0x0004:
			binary.Read(reader, binary.LittleEndian, &pi.Name.SizeOfProjectName)
			pi.Name.ProjectName = make([]uint8, pi.Name.SizeOfProjectName)
			err = binary.Read(reader, binary.LittleEndian, &pi.Name.ProjectName)
		case 0x0005:
			binary.Read(reader, binary.LittleEndian, &pi.DocString.SizeOfDocString)
			pi.DocString.DocString = make([]uint8, pi.DocString.SizeOfDocString)
			err = binary.Read(reader, binary.LittleEndian, &pi.DocString.DocString)
			if err != nil {
				return nil, err
			}
			binary.Read(reader, binary.LittleEndian, &pi.DocString.Reserved)
			binary.Read(reader, binary.LittleEndian, &pi.DocString.SizeOfDocStringUnicode)
			tmp16 := make([]uint16, pi.DocString.SizeOfDocStringUnicode/2)
			err = binary.Read(reader, binary.LittleEndian, &tmp16)
			pi.DocString.DocStringUnicode = string(utf16.Decode(tmp16))
		case 0x0006:
			binary.Read(reader, binary.LittleEndian, &pi.HelpFilePath.SizeOfHelpFile1)
			pi.HelpFilePath.HelpFile1 = make([]uint8, pi.HelpFilePath.SizeOfHelpFile1)
			err = binary.Read(reader, binary.LittleEndian, &pi.HelpFilePath.HelpFile1)
			if err != nil {
				return nil, err
			}
			binary.Read(reader, binary.LittleEndian, &pi.HelpFilePath.Reserved)
			binary.Read(reader, binary.LittleEndian, &pi.HelpFilePath.SizeOfHelpFile2)
			pi.HelpFilePath.HelpFile2 = make([]uint8, pi.HelpFilePath.SizeOfHelpFile2)
			err = binary.Read(reader, binary.LittleEndian, &pi.HelpFilePath.HelpFile2)
		case 0x0007:
			err = binary.Read(reader, binary.LittleEndian, &pi.HelpContext)
		case 0x0008:
			err = binary.Read(reader, binary.LittleEndian, &pi.LibFlags)
		case 0x0009:
			err = binary.Read(reader, binary.LittleEndian, &pi.Version)
		case 0x000c:
			binary.Read(reader, binary.LittleEndian, &pi.Constants.SizeOfConstants)
			pi.Constants.Constants = make([]uint8, pi.Constants.SizeOfConstants)
			err = binary.Read(reader, binary.LittleEndian, &pi.Constants.Constants)
			if err != nil {
				return nil, err
			}
			binary.Read(reader, binary.LittleEndian, &pi.Constants.Reserved)
			binary.Read(reader, binary.LittleEndian, &pi.Constants.SizeOfConstantsUnicode)
			pi.Constants.ConstantsUnicode = make([]uint8, pi.Constants.SizeOfConstantsUnicode)
			err = binary.Read(reader, binary.LittleEndian, &pi.Constants.ConstantsUnicode)
			if err != nil {
				return nil, err
			}
			// final entry for ProjectInformation
			return &pi, nil
		default:
			err = fmt.Errorf("unknown project info record id: %d", nid)
		}
		if err != nil {
			return nil, err
		}

	}
}
