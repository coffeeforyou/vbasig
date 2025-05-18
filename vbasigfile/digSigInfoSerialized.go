package vbasigfile

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/coffeeforyou/vbasig/pkcs7"
)

type DigSigInfoSerializedHeader struct {
	CbSignature        uint32 //size of the pbSignatureBuffer field
	SignatureOffset    uint32 // offset of the pbSignatureBuffer field (typically 44)
	CbSigningCertStore uint32 // size of the pbSigningCertStoreBuffer field
	CertStoreOffset    uint32 // offset of the pbSigningCertStoreBuffer field (SignatureOffset + CbSignature)
	CbProjectName      uint32 // count in bytes of the rgchProjectNameBuffer field, must be 0x00000000
	ProjectNameOffset  uint32 // offset of the rgchProjectNameBuffer field, depending on parent
	FTimestamp         uint32 // Reserved, must be 0x00000000
	CbTimestampUrl     uint32 // count in bytes of the rgchTimestampBuffer field
	TimestampUrlOffset uint32 // offset of the rgchTimestampBuffer field, depending on parent
}

type DigSigInfoSerialized struct {
	DigSigInfoSerializedHeader
	PbSignatureBuffer        []byte // array of bytes that specifies the VBA Digital Signature
	PbSigningCertStoreBuffer []byte // VBASigSerializedCertStore containing information of the certificate used
	RgchProjectNameBuffer    []byte // Reserved, must be 0x0000
	RgchTimestampBuffer      []byte // Reserved, must be 0x0000

	PbSignature        *pkcs7.PKCS7 // parsed PbSignatureBuffer
	PbSigningCertStore *VBASigSerializedCertStore
}

func NewDigSigInfoSerialized(pbSignature []byte, signCert x509.Certificate) (*DigSigInfoSerialized, error) {
	res := DigSigInfoSerialized{}
	res.CbProjectName = 0x00000000
	res.FTimestamp = 0x00000000
	res.RgchProjectNameBuffer = []byte{0, 0}
	res.RgchTimestampBuffer = []byte{0, 0}
	res.SignatureOffset = 44
	res.ReplaceSigBuffer(pbSignature)
	certStore, err := NewVbaSigSerializedCertStore(signCert)
	if err != nil {
		return nil, err
	}
	res.ReplaceCertStore(certStore)
	return &res, nil
}

func (sigBlob *DigSigInfoSerialized) FixOffsets() {
	sigBlob.CertStoreOffset = sigBlob.SignatureOffset + sigBlob.CbSignature
	sigBlob.ProjectNameOffset = sigBlob.CertStoreOffset + sigBlob.CbSigningCertStore
	sigBlob.TimestampUrlOffset = sigBlob.ProjectNameOffset + uint32(len(sigBlob.RgchProjectNameBuffer))
}

func (sigBlob *DigSigInfoSerialized) ReplaceSigBuffer(b []byte) {
	sigBlob.CbSignature = uint32(len(b))
	sigBlob.PbSignatureBuffer = b
	sigBlob.FixOffsets()
}

func (sigBlob *DigSigInfoSerialized) ReplaceCertStore(s []byte) {
	sigBlob.PbSigningCertStoreBuffer = s
	sigBlob.CbSigningCertStore = uint32(len(sigBlob.PbSigningCertStoreBuffer))
	sigBlob.FixOffsets()
}

func ParseDigSigInfoSerialized(data []byte) (*DigSigInfoSerialized, error) {
	var sigBlob DigSigInfoSerialized
	// Reading fixed fields
	bc, err := binary.Decode(data, binary.LittleEndian, &sigBlob.DigSigInfoSerializedHeader)
	if err != nil || bc != 36 {
		return nil, fmt.Errorf("decoding DigSigInfoSerializedHeader failed")
	}
	// Check reserved fields (should be zero)
	if sigBlob.FTimestamp != 0 || sigBlob.CbProjectName != 0 || sigBlob.CbTimestampUrl != 0 {
		return nil, errors.New("reserved fields should be zero")
	}
	// Now extract variable-length fields based on the offsets and sizes
	// Start with offset of 36 (=header size). Offsets in structure might be inaccurate, since based on representation in memory and depending on Office file type.
	var offset uint32 = 36
	// SignatureBuffer
	sigBlob.PbSignatureBuffer = data[offset : offset+sigBlob.CbSignature]
	sigBlob.PbSignature, err = pkcs7.Parse(sigBlob.PbSignatureBuffer)
	if err != nil {
		return nil, fmt.Errorf("parsing pkcs#7 failed")
	}
	offset += sigBlob.CbSignature

	// SigningCertStoreBuffer
	sigBlob.PbSigningCertStoreBuffer = data[offset : offset+sigBlob.CbSigningCertStore]
	sigBlob.PbSigningCertStore, err = ParseVBASigSerializedCertStore(bytes.NewReader(sigBlob.PbSigningCertStoreBuffer))

	if err != nil {
		return nil, fmt.Errorf("parsing certificate store failed")
	}
	offset += sigBlob.CbSigningCertStore

	// ProjectNameBuffer - expects only a null-terminated Unicode string
	sigBlob.RgchProjectNameBuffer = data[offset : offset+2]
	offset += 2
	// TimestampBuffer - expects only a null-terminated Unicode string
	sigBlob.RgchTimestampBuffer = data[offset : offset+2]

	return &sigBlob, nil
}

func (sigBlob *DigSigInfoSerialized) Write(w io.Writer) (int, error) {
	buf := make([]byte, 36)
	binary.Encode(buf, binary.LittleEndian, sigBlob.DigSigInfoSerializedHeader)
	buf = append(buf, sigBlob.PbSignatureBuffer...)
	buf = append(buf, sigBlob.PbSigningCertStoreBuffer...)
	buf = append(buf, sigBlob.RgchProjectNameBuffer...)
	buf = append(buf, sigBlob.RgchTimestampBuffer...)
	return w.Write(buf)
}

func (sigBlob *DigSigInfoSerialized) Serialize() []byte {
	buf := make([]byte, 36)
	binary.Encode(buf, binary.LittleEndian, sigBlob.DigSigInfoSerializedHeader)
	buf = append(buf, sigBlob.PbSignatureBuffer...)
	buf = append(buf, sigBlob.PbSigningCertStoreBuffer...)
	buf = append(buf, sigBlob.RgchProjectNameBuffer...)
	buf = append(buf, sigBlob.RgchTimestampBuffer...)
	return buf
}
