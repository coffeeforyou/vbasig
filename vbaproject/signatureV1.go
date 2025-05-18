package vbaproject

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"strings"

	"github.com/coffeeforyou/vbasig/pkcs7"
	"github.com/coffeeforyou/vbasig/util"
)

// Returns the pkcs7 (detached signature bytes)
func GetProjectSignatureV1(p *VbaProject, certWithKey *tls.Certificate, caCerts []*x509.Certificate) ([]byte, error) {
	// Get content info
	content, err := p.GetContentInfo()
	util.TerminateIfErr(err)
	// Initialize signature
	signature, err := pkcs7.NewSignedMsData(content)
	util.TerminateIfErr(err)
	// Setting algorithm to MD5
	signature.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmMD5)
	// Add signer
	msAttribute := pkcs7.Attribute{Type: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 12}, Value: asn1.NullRawValue}
	err = signature.AddSignerChain(certWithKey.Leaf, certWithKey.PrivateKey, caCerts, pkcs7.SignerInfoConfig{ExtraSignedAttributes: []pkcs7.Attribute{msAttribute}})
	util.TerminateIfErr(err)
	// Convert to bytes
	return signature.Finish()
}

// encapContentInfo -> eContent -> SEQUENCE
func (p *VbaProject) GetContentInfo() ([]byte, error) {
	content := SpcIndirectDataContent{}
	content.Data.Type = OIDSpcAttrType
	content.Data.Value = asn1.RawValue{Tag: 0x04, Bytes: []byte{}}
	content.MessageDigest.DigestAlgorithm = AlgorithmIdentifier{Algorithm: pkcs7.OIDDigestAlgorithmMD5}
	content.MessageDigest.DigestAlgorithm.Parameters = asn1.NullRawValue
	content.MessageDigest.Digest = getHashV1(p)
	return asn1.Marshal(content)
}

// SET CryptographicDigest TO the cryptographic digest of the ContentNormalizedData Buffer,
// as generated in the Content Normalized Data (section 2.4.2.1), as specified by the hashing algorithm.
func getHashV1(p *VbaProject) []byte {
	h := md5.New()
	h.Write(contentNormalizedData(p))
	return h.Sum(nil)
}

// 2.4.2.1 Content Normalized Data
func contentNormalizedData(p *VbaProject) []byte {
	buf := bytes.Buffer{}
	// APPEND Buffer WITH PROJECTNAME.ProjectName (section 2.3.4.2.1.6) of Storage
	buf.Write(p.DirStream.InformationRecord.Name.ProjectName)
	// APPEND Buffer WITH PROJECTCONSTANTS.Constants (section 2.3.4.2.1.12) of Storage
	buf.Write(p.DirStream.InformationRecord.Constants.Constants)
	// FOR EACH REFERENCE (section 2.3.4.2.2.1) IN PROJECTREFERENCES.ReferenceArray
	for _, ref := range p.DirStream.ReferencesRecord.ReferenceArray {
		// IF REFERENCE.ReferenceRecord.Id = 0x000D THEN APPEND Buffer with 0x7B
		if ref.RegisteredReference != nil {
			buf.Write([]byte{0x7B})
			continue
		}
		// ELSE IF REFERENCE.ReferenceRecord.Id = 0x000E THEN ...
		if ref.ProjectReference != nil {
			refBuf := bytes.Buffer{}
			tmp4 := make([]byte, 4) // to convert uint32 values
			// APPEND TempBuffer WITH REFERENCE.ReferenceRecord.SizeOfLibidAbsolute
			binary.Encode(tmp4, binary.LittleEndian, ref.ProjectReference.SizeOfLibidAbsolute)
			refBuf.Write(tmp4)
			// APPEND TempBuffer WITH REFERENCE.ReferenceRecord.LibidAbsolute
			refBuf.Write(ref.ProjectReference.LibidAbsolute)
			// APPEND TempBuffer WITH REFERENCE.ReferenceRecord.SizeOfLibidRelative
			binary.Encode(tmp4, binary.LittleEndian, ref.ProjectReference.SizeOfLibidRelative)
			refBuf.Write(tmp4)
			// APPEND TempBuffer WITH REFERENCE.ReferenceRecord.LibidRelative
			refBuf.Write(ref.ProjectReference.LibidRelative)
			// APPEND TempBuffer WITH REFERENCE.ReferenceRecord.MajorVersion
			binary.Encode(tmp4, binary.LittleEndian, ref.ProjectReference.MajorVersion)
			refBuf.Write(tmp4)
			// APPEND TempBuffer WITH REFERENCE.ReferenceRecord.MinorVersion
			binary.Encode(tmp4, binary.LittleEndian, ref.ProjectReference.MinorVersion)
			refBuf.Write(tmp4)
			// APPEND TempBuffer WITH 0x00
			refBuf.Write([]byte{0x00})
			// write bytes until 0x00
			var b byte
			for b, _ = refBuf.ReadByte(); b != 0x00; b, _ = refBuf.ReadByte() {
				buf.WriteByte(b)
			}
		}
	}
	//  FOR EACH ModuleStream (section 2.3.4.3) IN VBA Storage (section 2.3.4) of Storage
	for _, ms := range p.ModuleStream.Modules {
		vbaString := string(ms.SourceCode)
		lines := parseModule([]byte(vbaString))
		for _, byteLine := range lines {
			line := string(byteLine)
			if strings.HasPrefix(strings.ToLower(line), "attribute") {
				continue
			}
			buf.WriteString(line)
		}
	}
	return buf.Bytes()
}

func parseModule(text []byte) [][]byte {
	var lines [][]byte
	var textBuffer []byte
	var previousChar byte

	for _, char := range text {
		if char == 0x0d || (char == 0x0a && previousChar != 0x0d) {
			// Newline encountered
			lines = append(lines, textBuffer)
			textBuffer = []byte{}
		} else {
			if char != 0x0a {
				textBuffer = append(textBuffer, char)
			}
		}
		previousChar = char
	}
	// Append the final buffer
	lines = append(lines, textBuffer)
	return lines
}
