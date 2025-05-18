package vbaproject

import (
	"encoding/asn1"
)

// Constants for known Object Identifiers
var (
	OIDSpcAttrType  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 29}
	OIDSpcAttrType2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 31}
)

//	SpcIndirectDataContent ::= SEQUENCE {
//	    data               SpcAttributeTypeAndOptionalValue,
//	    messageDigest      DigestInfo
//	}
type SpcIndirectDataContent struct {
	Data          SpcAttributeTypeAndOptionalValue `asn1:"sequence"`
	MessageDigest DigestInfo                       `asn1:"sequence"`
}

//	SpcIndirectDataContentV2 ::= SEQUENCE {
//	    data               SpcAttributeTypeAndOptionalValue,
//	    messageDigest      DigestInfo
//	}
type SpcIndirectDataContentV2 struct {
	Data          SpcAttributeTypeAndOptionalValue `asn1:"sequence"`
	MessageDigest DigestInfo                       `asn1:"sequence"`
}

//	SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
//	    type                OBJECT IDENTIFIER,
//	    value               [0] EXPLICIT ANY OPTIONAL
//	}
//
// The type field MUST be an Object Identifier ([ITUX680-1994] section 3.8.35) with the value 1.3.6.1.4.1.311.2.1.29.
// The value field SHOULD be set to a zero byte OCTETSTRING ([ITUX680-1994] section 20). If the field has any data associated with it, the data MUST be ignored.
type SpcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier `asn1:"objectidentifier"`
	Value asn1.RawValue         `asn1:"explicit,optional,tag:0"`
}

//	DigestInfo ::= SEQUENCE {
//	    digestAlgorithm    AlgorithmIdentifier,
//	    digest             OCTETSTRING
//	}
type DigestInfo struct {
	DigestAlgorithm AlgorithmIdentifier `asn1:"sequence"`
	Digest          []byte              `asn1:"octet"`
}

//	AlgorithmIdentifier ::= SEQUENCE {
//	    algorithm          OBJECT IDENTIFIER,
//	    parameters         [0] EXPLICIT ANY OPTIONAL
//	}
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier `asn1:"objectidentifier"`
	Parameters asn1.RawValue         `asn1:"explicit,optional,tag:0"`
}

//	SigFormatDescriptorV1 ::= SEQUENCE {
//	    size               INTEGER,
//	    version            INTEGER,
//	    format             INTEGER
//	}
type SigFormatDescriptorV1 struct {
	Size    uint32 // MUST be equal to the size of the structure, = 3x4 bytes
	Version uint32
	Format  uint32
}

//	SigDataV1Serialized ::= SEQUENCE {
//	    algorithmIdSize    INTEGER,
//	    compiledHashSize   INTEGER,
//	    sourceHashSize     INTEGER,
//	    algorithmIdOffset  INTEGER,
//	    compiledHashOffset INTEGER,
//	    sourceHashOffset   INTEGER,
//	    algorithmId        OBJECT IDENTIFIER,
//	    compiledHash
//	    sourceHash         OCTETSTRING
//	}
type SigDataV1SerializedHeader struct {
	AlgorithmIdSize    int32
	CompiledHashSize   int32
	SourceHashSize     int32
	AlgorithmIdOffset  int32
	CompiledHashOffset int32
	SourceHashOffset   int32
	// algorithmId, compiledHash, sourceHash as []byte
}
