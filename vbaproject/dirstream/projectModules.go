package dirstream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// PROJECTMODULES Record
type ProjectModules struct {
	Size          uint32         // MUST be 0x00000002
	Count         uint16         // Number of modules
	ProjectCookie *ProjectCookie // 8-byte PROJECTCOOKIE record
	Modules       []Module       // MODULE records
}

// PROJECTCOOKIE Record
type ProjectCookie struct {
	Size   uint32 // MUST be 0x00000002
	Cookie uint16 // MUST be ignored on read, 0xFFFF on write
}

// MODULE Record
type Module struct {
	NameRecord        ModuleNameRecord         // Required
	NameUnicodeRecord *ModuleNameUnicodeRecord // Optional
	StreamNameRecord  ModuleStreamNameRecord   // Required
	DocStringRecord   ModuleDocStringRecord    // Required
	OffsetRecord      ModuleOffsetRecord       // 10 bytes
	HelpContextRecord ModuleHelpContextRecord  // 10 bytes
	CookieRecord      ModuleCookieRecord       // 8 bytes
	TypeRecord        ModuleTypeRecord         // 6 bytes
	ReadOnlyRecord    *ModuleReadOnlyRecord    // Optional, 6 bytes
	PrivateRecord     *ModulePrivateRecord     // Optional, 6 bytes
	Reserved          uint32                   // MUST be 0x00000000, ignored
}

// MODULENAME Record
type ModuleNameRecord struct {
	SizeOfModuleName uint32
	ModuleName       []byte // MBCS encoded, SizeOfModuleName bytes, no nulls
}

// MODULENAMEUNICODE Record (optional)
type ModuleNameUnicodeRecord struct {
	SizeOfModuleNameUnicode uint32 // MUST be even
	ModuleNameUnicode       []byte // UTF-16 encoded, SizeOfModuleNameUnicode bytes, no nulls
}

// MODULESTREAMNAME Record
type ModuleStreamNameRecord struct {
	SizeOfStreamName        uint32
	StreamName              []byte // MBCS encoded, no nulls
	Reserved                uint16 // MUST be 0x0032, ignored
	SizeOfStreamNameUnicode uint32 // MUST be even
	StreamNameUnicode       []byte // UTF-16 encoded, no nulls
}

// MODULEDOCSTRING Record
type ModuleDocStringRecord struct {
	SizeOfDocString        uint32
	DocString              []byte // MBCS encoded, no nulls
	Reserved               uint16 // MUST be 0x0048, ignored
	SizeOfDocStringUnicode uint32 // MUST be even
	DocStringUnicode       []byte // UTF-16 encoded, no nulls
}

// MODULEOFFSET Record
type ModuleOffsetRecord struct {
	Size       uint32 // MUST be 0x00000004
	TextOffset uint32 // Offset into the ModuleStream
}

// MODULEHELPCONTEXT Record
type ModuleHelpContextRecord struct {
	Size        uint32 // MUST be 0x00000004
	HelpContext uint32 // Help topic ID
}

// MODULECOOKIE Record
type ModuleCookieRecord struct {
	Size   uint32 // MUST be 0x00000002
	Cookie uint16 // MUST be 0xFFFF on write, ignored on read
}

// MODULETYPE Record
type ModuleTypeRecord struct {
	Id       uint16 // MUST be 0x0021 when procedural module. MUST be 0x0022 when document module, class module, or designer module.
	Reserved uint32 // MUST be 0x00000000, ignored
}

// MODULEREADONLY Record (optional)
type ModuleReadOnlyRecord struct {
	Reserved uint32 // MUST be 0x00000000, ignored
}

// MODULEPRIVATE Record (optional)
type ModulePrivateRecord struct {
	Reserved uint32 // MUST be 0x00000000, ignored
}

// Parse the binary data
func ParseProjectModules(reader *bytes.Reader, pi *ProjectInformation) (*ProjectModules, error) {
	var pm ProjectModules
	// Read and parse records depending on record id
	var nid uint16
	var err error

	binary.Read(reader, binary.LittleEndian, &pm.Size)
	binary.Read(reader, binary.LittleEndian, &pm.Count)
	pm.ProjectCookie, err = parseProjectCookie(reader)
	if err != nil {
		return nil, err
	}
	// Read and parse pm.Count modules
	var tmp Module
	for len(pm.Modules) < int(pm.Count) {
		err := binary.Read(reader, binary.LittleEndian, &nid)
		if err != nil {
			return nil, fmt.Errorf("failed to read id (module): %w", err)
		}
		switch nid {
		case 0x0019: // MODULENAME Record
			tmp = Module{}
			binary.Read(reader, binary.LittleEndian, &tmp.NameRecord.SizeOfModuleName)
			tmp.NameRecord.ModuleName = make([]byte, tmp.NameRecord.SizeOfModuleName)
			binary.Read(reader, binary.LittleEndian, &tmp.NameRecord.ModuleName)
		case 0x0047: // MODULENAMEUNICODE Record
			tmp.NameUnicodeRecord = &ModuleNameUnicodeRecord{}
			binary.Read(reader, binary.LittleEndian, &tmp.NameUnicodeRecord.SizeOfModuleNameUnicode)
			tmp.NameUnicodeRecord.ModuleNameUnicode = make([]byte, tmp.NameUnicodeRecord.SizeOfModuleNameUnicode)
			binary.Read(reader, binary.LittleEndian, &tmp.NameUnicodeRecord.ModuleNameUnicode)
		case 0x001a: // MODULESTREAMNAME Record
			binary.Read(reader, binary.LittleEndian, &tmp.StreamNameRecord.SizeOfStreamName)
			tmp.StreamNameRecord.StreamName = make([]byte, tmp.StreamNameRecord.SizeOfStreamName)
			binary.Read(reader, binary.LittleEndian, &tmp.StreamNameRecord.StreamName)
			binary.Read(reader, binary.LittleEndian, &tmp.StreamNameRecord.Reserved)
			if tmp.StreamNameRecord.Reserved != 0x0032 {
				return nil, fmt.Errorf("reserved constant of MODULESTREAM record incorrect: %x", tmp.StreamNameRecord.Reserved)
			}
			binary.Read(reader, binary.LittleEndian, &tmp.StreamNameRecord.SizeOfStreamNameUnicode)
			tmp.StreamNameRecord.StreamNameUnicode = make([]byte, tmp.StreamNameRecord.SizeOfStreamNameUnicode)
			binary.Read(reader, binary.LittleEndian, &tmp.StreamNameRecord.StreamNameUnicode)
		case 0x001c: // MODULEDOCSTRING Record
			binary.Read(reader, binary.LittleEndian, &tmp.DocStringRecord.SizeOfDocString)
			tmp.DocStringRecord.DocString = make([]byte, tmp.DocStringRecord.SizeOfDocString)
			binary.Read(reader, binary.LittleEndian, &tmp.DocStringRecord.DocString)
			binary.Read(reader, binary.LittleEndian, &tmp.DocStringRecord.Reserved)
			binary.Read(reader, binary.LittleEndian, &tmp.DocStringRecord.SizeOfDocStringUnicode)
			tmp.DocStringRecord.DocStringUnicode = make([]byte, tmp.DocStringRecord.SizeOfDocStringUnicode)
			binary.Read(reader, binary.LittleEndian, &tmp.DocStringRecord.DocStringUnicode)
		case 0x0031: // MODULEOFFSET Record
			binary.Read(reader, binary.LittleEndian, &tmp.OffsetRecord.Size)
			binary.Read(reader, binary.LittleEndian, &tmp.OffsetRecord.TextOffset)
		case 0x001e: // MODULEHELPCONTEXT Record
			binary.Read(reader, binary.LittleEndian, &tmp.HelpContextRecord.Size)
			binary.Read(reader, binary.LittleEndian, &tmp.HelpContextRecord.HelpContext)
		case 0x002c: // MODULECOOKIE Record
			binary.Read(reader, binary.LittleEndian, &tmp.CookieRecord.Size)
			binary.Read(reader, binary.LittleEndian, &tmp.CookieRecord.Cookie)
		case 0x0021: // MODULETYPE Record
			tmp.TypeRecord.Id = 0x0021
			binary.Read(reader, binary.LittleEndian, &tmp.TypeRecord.Reserved)
		case 0x0022: // MODULETYPE Record
			tmp.TypeRecord.Id = 0x0022
			binary.Read(reader, binary.LittleEndian, &tmp.TypeRecord.Reserved)
		case 0x0025: // MODULEREADONLY Record
			tmp.ReadOnlyRecord = &ModuleReadOnlyRecord{}
			binary.Read(reader, binary.LittleEndian, &tmp.ReadOnlyRecord.Reserved)
		case 0x0028: // MODULEPRIVATE Record
			tmp.PrivateRecord = &ModulePrivateRecord{}
			binary.Read(reader, binary.LittleEndian, &tmp.PrivateRecord.Reserved)
		case 0x002b: // TERMINATOR Record
			binary.Read(reader, binary.LittleEndian, &tmp.Reserved)
			pm.Modules = append(pm.Modules, tmp)
		default:
			err = fmt.Errorf("unknown module record id: %d", nid)
		}
		if err != nil {
			return nil, err
		}
	}
	return &pm, nil
}

func parseProjectCookie(reader io.Reader) (*ProjectCookie, error) {
	var nid uint16
	tmp := ProjectCookie{}
	binary.Read(reader, binary.LittleEndian, &nid)
	if nid != 0x0013 {
		return nil, fmt.Errorf("invalid id for project cookie")
	}
	binary.Read(reader, binary.LittleEndian, &tmp.Size)
	binary.Read(reader, binary.LittleEndian, &tmp.Cookie)
	return &tmp, nil
}
