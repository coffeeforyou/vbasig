package vbacompression

import (
	"encoding/binary"
	"fmt"
)

// The CompressedContainer is a SignatureByte followed by array of CompressedChunk structures.
func DecompressContainer(compressedData []byte) ([]byte, uint16, error) {
	// Keep track of position in compressed data
	var pos uint16 = 0
	// all decompressed data
	decompressedBuffer := []uint8{}
	// Check signature byte
	if compressedData[pos] != 0x01 {
		return nil, 0, fmt.Errorf("invalid signature byte")
	}
	pos++
	// Decompress chunks until no data left
	for pos < uint16(len(compressedData)-1) {
		decompressedBufferNew, newPos, err := decompressChunk(compressedData, pos, decompressedBuffer)
		if err != nil {
			return nil, 0, err
		}
		decompressedBuffer = decompressedBufferNew
		pos = newPos
	}
	return decompressedBuffer, pos, nil
}

func decompressChunk(compressedData []byte, pos uint16, decompressedBuffer []byte) ([]byte, uint16, error) {
	// Read the header, first 2 bytes
	headerBits := binary.LittleEndian.Uint16(compressedData[pos : pos+2])
	pos += 2
	// CompressedChunkSize is an unsigned integer that specifies the number of bytes in the CompressedChunk minus 3 (-1 and 2 header bytes). MUST be greater than or equal to zero.
	// If CompressedChunkFlag is equal to 0b1, this element MUST be less than or equal to 4095. If CompressedChunkFlag is equal to 0b0, this element MUST be 4095.
	compressedChunkSize := (headerBits & 0b0000_1111_1111_1111)            // only 12 bits on the right relevant.
	compressedChunkSignature := (headerBits & 0b0111_0000_0000_0000) >> 12 // constant 3 bits, must be 011
	compressedChunkFlag := (headerBits & 0b1000_0000_0000_0000) >> 15      // only first bit relevant
	// sanity checks
	if compressedChunkSignature != 0b011 {
		return nil, 0, fmt.Errorf("invalid chunk signature at pos %d of %d ", pos, len(compressedData))
	}
	if compressedChunkSize < 3 || (compressedChunkFlag == 1 && compressedChunkSize > 4095) || (compressedChunkFlag == 0 && compressedChunkSize != 4095) {
		return nil, 0, fmt.Errorf("invalid combination of chunk flag %d and chunk size %d at pos %d of %d", compressedChunkFlag, compressedChunkSize, pos, len(compressedData))
	}
	// last byte of chunk in compressed data
	var chunkEndPos uint16 = pos + compressedChunkSize
	// The location of the first byte of the DecompressedChunk within the DecompressedBuffer
	var decompressedChunkStart = uint16(len(decompressedBuffer))

	// Determine if uncompress chunk based on flag
	if compressedChunkFlag == 1 {
		var err error
		for pos < chunkEndPos {
			decompressedBuffer, pos, err = decompressTokenSequence(compressedData, pos, decompressedBuffer, chunkEndPos, decompressedChunkStart)
			if err != nil {
				return nil, 0, err
			}
		}
	} else {
		// uncompressed data, just copy
		decompressedBuffer = append(decompressedBuffer, compressedData[pos:pos+4096]...)
		pos = pos + 4096
	}
	return decompressedBuffer, pos, nil
}

func decompressTokenSequence(compressedData []byte, pos uint16, decompressedBuffer []byte, chunkEndPos uint16, decompressedChunkStart uint16) ([]byte, uint16, error) {
	// Keeping track of errors
	var err error
	// FlagByte (1 byte): Each bit specifies the type of a Token in the TokenSequence. A value of 0b0 specifies a LiteralToken. A value of 0b1 specifies a CopyToken.
	flagByte := compressedData[pos]
	pos++
	for range 8 {
		switch flagByte & 0b0000_0001 {
		case 0x00:
			literalToken := compressedData[pos]
			decompressedBuffer = append(decompressedBuffer, literalToken)
			pos++
		case 0x01:
			decompressedBuffer, pos, err = decodeCopyToken(compressedData, pos, decompressedBuffer, decompressedChunkStart)
			if err != nil {
				return nil, 0, err
			}
		}
		if pos >= chunkEndPos {
			if pos == chunkEndPos {
				decompressedBuffer = append(decompressedBuffer, compressedData[pos])
			}
			pos = chunkEndPos + 1
			break
		}
		flagByte = flagByte >> 1
	}
	return decompressedBuffer, pos, nil
}

func decodeCopyToken(compressedData []byte, pos uint16, decompressedBuffer []byte, decompressedChunkStart uint16) ([]byte, uint16, error) {
	copyToken := binary.LittleEndian.Uint16(compressedData[pos : pos+2])
	// number of bits in copyToken for length of copied sequence, function expects DecompressedCurrent minus DecompressedChunkStart
	tokenLenBitCount, err := getCopyTokenOffsetBitCount(uint16(len(decompressedBuffer)) - decompressedChunkStart)
	if err != nil {
		return nil, 0, err
	}
	// number of bits in copyToken for offset of copied sequence
	tokenOffBitCount := 16 - tokenLenBitCount
	// split copyToken to determine offset and length
	lengthmask := ^uint16(0) >> tokenOffBitCount
	// Length is the number of bytes minus three in the CopySequence.
	tokenLen := uint16(copyToken&lengthmask) + 3
	// Offset is the difference between DecompressedCurrent and the start of the CopySequence minus one.
	// tokenOff = DecompressedCurrent - copyStart - 1  -> copyStart = DecompressedCurrent - tokenOff - 1
	tokenOff := uint16(copyToken >> (tokenLenBitCount))
	// position in already decompressed data where copied byte sequence with tokenLen starts
	copyStart := uint16(len(decompressedBuffer)) - tokenOff - 1
	for range tokenLen {
		decompressedBuffer = append(decompressedBuffer, decompressedBuffer[copyStart])
		copyStart++
	}
	return decompressedBuffer, pos + 2, nil
}

func getCopyTokenOffsetBitCount(decompressedBufferLength uint16) (uint16, error) {
	if decompressedBufferLength <= 16 {
		return 12, nil
	}
	if decompressedBufferLength <= 32 {
		return 11, nil
	}
	if decompressedBufferLength <= 64 {
		return 10, nil
	}
	if decompressedBufferLength <= 128 {
		return 9, nil
	}
	if decompressedBufferLength <= 256 {
		return 8, nil
	}
	if decompressedBufferLength <= 512 {
		return 7, nil
	}
	if decompressedBufferLength <= 1024 {
		return 6, nil
	}
	if decompressedBufferLength <= 2048 {
		return 5, nil
	}
	if decompressedBufferLength <= 4096 {
		return 4, nil
	}
	return 0, fmt.Errorf("decompressed data length too high")
}
