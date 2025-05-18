package vbasigfile

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Define the structure of the binary data format.
type SerializedPropertyEntry struct {
	ID           uint32 // 4 bytes: id, must be <= 0x0000FFFF and not 0x00000000 or 0x00000020
	EncodingType uint32 // 4 bytes: encodingType, must be 0x00000001
	Length       uint32 // 4 bytes: length, specifies the size of the value field
	Value        []byte // variable-length: the value of the property (which should be ignored)
}

// Read the binary structure into the SerializedPropertyEntry.
func ReadSerializedPropertyEntry(data []byte) (*SerializedPropertyEntry, []byte, error) {
	var property SerializedPropertyEntry

	// Check if the data has enough bytes to read id, encodingType, and length (12 bytes minimum)
	if len(data) < 12 {
		return nil, nil, errors.New("data too short, need at least 12 bytes")
	}

	// Read the fixed-size fields (id, encodingType, length).
	property.ID = binary.LittleEndian.Uint32(data[0:4])
	if property.ID == 0x00000000 || property.ID == 0x00000020 {
		return nil, nil, fmt.Errorf("invalid id: 0x%08x is reserved", property.ID)
	}
	if property.ID > 0x0000FFFF {
		return nil, nil, fmt.Errorf("invalid id: 0x%08x is greater than 0x0000FFFF", property.ID)
	}

	property.EncodingType = binary.LittleEndian.Uint32(data[4:8])
	if property.EncodingType != 0x00000001 {
		return nil, nil, fmt.Errorf("invalid encodingType: expected 0x00000001, got 0x%08x", property.EncodingType)
	}

	property.Length = binary.LittleEndian.Uint32(data[8:12])

	// Check if we have enough data to read the value field.
	if len(data) < int(12+property.Length) {
		return nil, nil, fmt.Errorf("data too short for value field: expected %d bytes, got %d", property.Length, len(data)-12)
	}

	// Read the value field (which we ignore).
	property.Value = data[12 : 12+property.Length]

	// Return the property data struct (we ignore the value field).
	return &property, data[12+property.Length:], nil
}
