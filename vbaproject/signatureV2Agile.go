package vbaproject

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"slices"

	"github.com/coffeeforyou/vbasig/pkcs7"
	"github.com/coffeeforyou/vbasig/util"
	"github.com/coffeeforyou/vbasig/vbaproject/modulestream"
)

// Returns the pkcs7 (detached signature bytes)
func GetProjectSignatureAgile(p *VbaProject, certWithKey *tls.Certificate, caCerts []*x509.Certificate) ([]byte, error) {
	// Get content info
	content, err := GetContentInfoV2(p)
	util.TerminateIfErr(err)
	// Initialize signature
	signature, err := pkcs7.NewSignedMsData(content)
	util.TerminateIfErr(err)
	// Setting algorithm to MD5
	signature.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	// Add signer
	msAttribute := pkcs7.Attribute{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}, Value: asn1.NullRawValue}
	err = signature.AddSignerChain(certWithKey.Leaf, certWithKey.PrivateKey, caCerts, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{msAttribute}})
	util.TerminateIfErr(err)
	// Convert to bytes
	return signature.Finish()
}

func GetContentInfoV2(p *VbaProject) ([]byte, error) {
	content := SpcIndirectDataContentV2{}
	content.Data.Type = OIDSpcAttrType2
	sfdv1 := SigFormatDescriptorV1{Size: 12, Version: 1, Format: 1}
	sfdv1Bytes := make([]byte, 12)
	_, err := binary.Encode(sfdv1Bytes, binary.LittleEndian, sfdv1)
	if err != nil {
		return nil, err
	}
	content.Data.Value = asn1.RawValue{Class: 0, Tag: 4, Bytes: sfdv1Bytes} // SigFormatDescriptorV1 structure
	content.MessageDigest.DigestAlgorithm = AlgorithmIdentifier{Algorithm: pkcs7.OIDDigestAlgorithmSHA256, Parameters: asn1.NullRawValue}
	algorithmId := []byte("2.16.840.1.101.3.4.2.1\x00")
	sourceHash := p.getHashAgile()
	algorithmIdSize := int32(len(algorithmId))
	sdv1 := SigDataV1SerializedHeader{
		AlgorithmIdSize:    algorithmIdSize,
		CompiledHashSize:   0,
		SourceHashSize:     int32(len(sourceHash)), // SHA256 is 32 bytes
		AlgorithmIdOffset:  6 * 4,                  // 6 x int32
		CompiledHashOffset: 6*4 + algorithmIdSize,  // 6*4 (int32) + 7*8 (algorithmId)
		SourceHashOffset:   6*4 + algorithmIdSize,  // 6*4 (int32) + 7*8 (algorithmId) + 0
	}
	sdv1Bytes := []byte{}
	// Start with bytes for header (fixed-size fields)
	sdv1Bytes, err = binary.Append(sdv1Bytes, binary.LittleEndian, sdv1)
	if err != nil {
		return nil, err
	}
	// AlgorithmId
	sdv1Bytes, err = binary.Append(sdv1Bytes, binary.LittleEndian, algorithmId)
	if err != nil {
		return nil, err
	}
	// No compiled hash, since The compiledHash field SHOULD be empty.
	// SourceHash
	sdv1Bytes, err = binary.Append(sdv1Bytes, binary.LittleEndian, sourceHash)
	if err != nil {
		return nil, err
	}
	content.MessageDigest.Digest = sdv1Bytes // SigDataV1Serialized structure
	return asn1.Marshal(content)
}

// Set ContentBuffer TO a resizable array of bytes
// APPEND ContentBuffer WITH the ContentNormalizedData Buffer, as generated in Content Normalized Data (section 2.4.2.1).
// APPEND ContentBuffer WITH the FormsNormalizedData Buffer, as generated in the Forms Normalized Data (section 2.4.2.2).
// SET CryptographicDigest TO the cryptographic digest of ContentBuffer as specified by the hashing algorithm.
func (p *VbaProject) getHashAgile() []byte {
	h := sha256.New()
	h.Write(contentNormalizedData(p))
	h.Write(formsNormalizedData(p))
	return h.Sum(nil)
}

// 2.4.2.2 Forms Normalized Data
func formsNormalizedData(p *VbaProject) []byte {
	buf := bytes.Buffer{}
	for _, m := range p.ModuleStream.Modules {
		// Designer Module?
		if slices.Contains(p.ProjectStream.ProjectDesignerModules, m.Name) {
			buf.Write(normalizeDesignerStorage(m))
		}
	}
	return buf.Bytes()
}

// NormalizeDesignerStorage
func normalizeDesignerStorage(m *modulestream.Module) []byte {
	buf := bytes.Buffer{}
	for _, cs := range m.ChildStreams {
		buf.Write(cs.Raw)
		blen := len(cs.Raw)
		padLen := 1023 - blen%1023
		buf.Write(make([]byte, padLen))
	}
	return buf.Bytes()
}
