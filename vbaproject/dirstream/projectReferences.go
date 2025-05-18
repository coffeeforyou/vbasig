package dirstream

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// Define struct for each record as per the specification
type ProjectReferences struct {
	ReferenceArray []Reference
}

// REFERENCE Record
type Reference struct {
	NameRecord          *ReferenceName
	ControlReference    *ReferenceControl
	RegisteredReference *ReferenceRegistered
	OriginalReference   *ReferenceOriginal
	ProjectReference    *ReferenceProject
}

// REFERENCENAME Record
type ReferenceName struct {
	SizeOfName        uint32
	Name              []byte // MBCS encoded string of length SizeOfName (no nulls)
	Reserved          uint16 // MUST be 0x003E, ignored on read
	SizeOfNameUnicode uint32
	NameUnicode       []byte // UTF-16 encoded string of length SizeOfNameUnicode (no nulls)
}

// GUID represents a 16-byte globally unique identifier
type GUID [16]byte

// REFERENCECONTROL Record
type ReferenceControl struct {
	SizeTwiddled        uint32 // MUST be ignored on read
	SizeOfLibidTwiddled uint32
	LibidTwiddled       []byte         // Size: SizeOfLibidTwiddled
	Reserved1           uint32         // MUST be 0x00000000, ignored
	Reserved2           uint16         // MUST be 0x0000, ignored
	NameRecordExtended  *ReferenceName // Optional REFERENCENAME Record (variable length)
	Reserved3           uint16         // MUST be 0x0030, ignored
	SizeExtended        uint32         // MUST be ignored on read
	SizeOfLibidExtended uint32
	LibidExtended       []byte // Size: SizeOfLibidExtended
	Reserved4           uint32 // MUST be 0x00000000, ignored
	Reserved5           uint16 // MUST be 0x0000, ignored
	OriginalTypeLib     GUID   // 16 bytes GUID
	Cookie              uint32 // Unique identifier
}

// REFERENCEREGISTERED Record
type ReferenceRegistered struct {
	Size        uint32 // Total size of SizeOfLibid + Libid + Reserved1 + Reserved2. MUST be ignored on read
	SizeOfLibid uint32
	Libid       []byte // Size: SizeOfLibid, MBCS encoded, no null characters
	Reserved1   uint32 // MUST be 0x00000000, ignored
	Reserved2   uint16 // MUST be 0x0000, ignored
}

// REFERENCEORIGINAL Record
type ReferenceOriginal struct {
	SizeOfLibidOriginal uint32
	LibidOriginal       []byte            // Size: SizeOfLibidOriginal, MBCS encoded, no null characters
	ReferenceRecord     *ReferenceControl // Variable size, full REFERENCECONTROL structure
}

// REFERENCEPROJECT Record
type ReferenceProject struct {
	Size                uint32 // Total size of all fields below. MUST be ignored on read.
	SizeOfLibidAbsolute uint32
	LibidAbsolute       []byte // Size: SizeOfLibidAbsolute, MBCS encoded, no nulls, absolute path
	SizeOfLibidRelative uint32
	LibidRelative       []byte // Size: SizeOfLibidRelative, MBCS encoded, no nulls, relative path
	MajorVersion        uint32 // VersionMajor of referenced project
	MinorVersion        uint16 // VersionMinor of referenced project
}

// Parse the binary data
func ParseProjectReferences(reader *bytes.Reader, pi *ProjectInformation) (*ProjectReferences, error) {
	var pr ProjectReferences
	// Read and parse records depending on record id
	var nid uint16
	var tmp Reference
	for {
		err := binary.Read(reader, binary.LittleEndian, &nid)
		if err != nil {
			return nil, fmt.Errorf("failed to read id (reference): %w", err)
		}
		switch nid {
		case 0x0016:
			tmp = Reference{}
			tmp.NameRecord, err = parseNameRecord(reader)
			if err != nil {
				return nil, err
			}
		case 0x002f: // REFERENCECONTROL
			tmp.ControlReference, err = parseControlRecord(reader)
			pr.ReferenceArray = append(pr.ReferenceArray, tmp)
		case 0x000d: // REFERENCEREGISTERED
			tmp.RegisteredReference = &ReferenceRegistered{}
			binary.Read(reader, binary.LittleEndian, &tmp.RegisteredReference.Size)
			binary.Read(reader, binary.LittleEndian, &tmp.RegisteredReference.SizeOfLibid)
			tmp.RegisteredReference.Libid = make([]byte, tmp.RegisteredReference.SizeOfLibid)
			binary.Read(reader, binary.LittleEndian, &tmp.RegisteredReference.Libid)
			binary.Read(reader, binary.LittleEndian, &tmp.RegisteredReference.Reserved1)
			binary.Read(reader, binary.LittleEndian, &tmp.RegisteredReference.Reserved2)
			pr.ReferenceArray = append(pr.ReferenceArray, tmp)
		case 0x0033: // REFERENCEORIGINAL
			tmp.OriginalReference = &ReferenceOriginal{}
			binary.Read(reader, binary.LittleEndian, &tmp.OriginalReference.SizeOfLibidOriginal)
			tmp.OriginalReference.LibidOriginal = make([]byte, tmp.OriginalReference.SizeOfLibidOriginal)
			binary.Read(reader, binary.LittleEndian, &tmp.OriginalReference.LibidOriginal)
			reader.Read(make([]byte, 2)) // ignore two bytes for control record id, must be 0x002f
			tmp.OriginalReference.ReferenceRecord, err = parseControlRecord(reader)
			pr.ReferenceArray = append(pr.ReferenceArray, tmp)
		case 0x000e: // REFERENCEPROJECT
			tmp.ProjectReference = &ReferenceProject{}
			binary.Read(reader, binary.LittleEndian, &tmp.ProjectReference.Size)
			binary.Read(reader, binary.LittleEndian, &tmp.ProjectReference.SizeOfLibidAbsolute)
			tmp.ProjectReference.LibidAbsolute = make([]byte, tmp.ProjectReference.SizeOfLibidAbsolute)
			binary.Read(reader, binary.LittleEndian, &tmp.ProjectReference.LibidAbsolute)
			binary.Read(reader, binary.LittleEndian, &tmp.ProjectReference.SizeOfLibidRelative)
			tmp.ProjectReference.LibidRelative = make([]byte, tmp.ProjectReference.SizeOfLibidRelative)
			binary.Read(reader, binary.LittleEndian, &tmp.ProjectReference.LibidRelative)
			binary.Read(reader, binary.LittleEndian, &tmp.ProjectReference.MajorVersion)
			binary.Read(reader, binary.LittleEndian, &tmp.ProjectReference.MinorVersion)
			pr.ReferenceArray = append(pr.ReferenceArray, tmp)
		case 0x000F: // ID to indicate beginning of modules, end of references
			return &pr, nil
		default:
			err = fmt.Errorf("unknown project reference record id: %d", nid)
		}
		if err != nil {
			return nil, err
		}

	}
}

func parseNameRecord(reader io.Reader) (*ReferenceName, error) {
	tmp := ReferenceName{}
	binary.Read(reader, binary.LittleEndian, &tmp.SizeOfName)
	tmp.Name = make([]byte, tmp.SizeOfName)
	binary.Read(reader, binary.LittleEndian, &tmp.Name)
	binary.Read(reader, binary.LittleEndian, &tmp.Reserved)
	binary.Read(reader, binary.LittleEndian, &tmp.SizeOfNameUnicode)
	tmp.NameUnicode = make([]byte, tmp.SizeOfNameUnicode)
	binary.Read(reader, binary.LittleEndian, &tmp.NameUnicode)
	return &tmp, nil
}

func parseControlRecord(reader io.Reader) (*ReferenceControl, error) {
	tmp := ReferenceControl{}
	var err error
	binary.Read(reader, binary.LittleEndian, &tmp.SizeTwiddled)
	binary.Read(reader, binary.LittleEndian, &tmp.SizeOfLibidTwiddled)
	tmp.LibidTwiddled = make([]byte, tmp.SizeOfLibidTwiddled)
	binary.Read(reader, binary.LittleEndian, &tmp.LibidTwiddled)
	binary.Read(reader, binary.LittleEndian, &tmp.Reserved1)
	binary.Read(reader, binary.LittleEndian, &tmp.Reserved2)
	var n2b uint16 // check if next two bytes are name record id or Reserved3
	binary.Read(reader, binary.LittleEndian, &n2b)
	if n2b == 0x0030 {
		tmp.Reserved3 = 0x0030
	} else {
		tmp.NameRecordExtended, err = parseNameRecord(reader)
		if err != nil {
			return nil, err
		}
		binary.Read(reader, binary.LittleEndian, &tmp.Reserved3)
	}
	binary.Read(reader, binary.LittleEndian, &tmp.SizeExtended)
	binary.Read(reader, binary.LittleEndian, &tmp.SizeOfLibidExtended)
	tmp.LibidExtended = make([]byte, tmp.SizeOfLibidExtended)
	binary.Read(reader, binary.LittleEndian, &tmp.LibidExtended)
	binary.Read(reader, binary.LittleEndian, &tmp.Reserved4)
	binary.Read(reader, binary.LittleEndian, &tmp.Reserved5)
	binary.Read(reader, binary.LittleEndian, &tmp.OriginalTypeLib)
	binary.Read(reader, binary.LittleEndian, &tmp.Cookie)
	return &tmp, nil
}
