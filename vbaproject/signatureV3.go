package vbaproject

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/coffeeforyou/vbasig/pkcs7"
	"github.com/coffeeforyou/vbasig/util"
	"github.com/coffeeforyou/vbasig/vbaproject/dirstream"
)

// Returns the pkcs7 (detached signature bytes)
func GetProjectSignatureV3(p *VbaProject, certWithKey *tls.Certificate, caCerts []*x509.Certificate) ([]byte, error) {
	// Get content info
	content, err := GetContentInfoV3(p)
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

func GetContentInfoV3(p *VbaProject) ([]byte, error) {
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
	sourceHash := getHashV3(p)
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
// APPEND ContentBuffer WITH the V3ContentNormalizedData Buffer, as generated in V3 Content Normalized Data (section 2.4.2.5).
// APPEND ContentBuffer WITH the ProjectNormalizedData Buffer, as generated in the Project Normalized Data (section 2.4.2.6).
// SET CryptographicDigest TO the cryptographic digest of ContentBuffer as specified by the hashing algorithm.
func getHashV3(p *VbaProject) []byte {
	var res []byte
	h := sha256.New()
	buf := contentNormalizedDataV3(p)
	buf = append(buf, projectNormalizedData(p)...)
	h.Write(buf)
	res = h.Sum(nil)
	return res
}

// 2.4.2.1 Content Normalized Data
func contentNormalizedDataV3(p *VbaProject) []byte {
	buf := []byte{}
	// APPEND Buffer WITH PROJECTSYSKIND.Id (section 2.3.4.2.1.1) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0001)) //  MUST be 0x0001
	// APPEND Buffer WITH PROJECTSYSKIND.Size (section 2.3.4.2.1.1) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000004)) //  MUST be 0x00000004
	// APPEND Buffer WITH PROJECTLCID.Id (section 2.3.4.2.1.3) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0002)) //  MUST be 0x0002
	// APPEND Buffer WITH PROJECTLCID.Size (section 2.3.4.2.1.3) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000004)) //  MUST be 0x00000004
	// APPEND Buffer WITH PROJECTLCID.Lcid (section 2.3.4.2.1.3) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000409)) // MUST be 0x00000409
	// APPEND Buffer WITH PROJECTLCIDINVOKE.Id (section 2.3.4.2.1.4) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0014)) // MUST be 0x0014
	// APPEND Buffer WITH PROJECTLCIDINVOKE.Size (section 2.3.4.2.1.4) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000004)) // MUST be 0x00000004
	// APPEND Buffer WITH PROJECTLCIDINVOKE.LcidInvoke (section 2.3.4.2.1.4) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000409)) // MUST be 0x00000409
	// APPEND Buffer WITH PROJECTCODEPAGE.Id (section 2.3.4.2.1.5) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0003)) // MUST be 0x0003
	// APPEND Buffer WITH PROJECTCODEPAGE.Size (section 2.3.4.2.1.5) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000002)) // MUST be 0x00000002
	// APPEND Buffer WITH PROJECTNAME.Id (section 2.3.4.2.1.6) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0004)) // MUST be 0x0004
	// APPEND Buffer WITH PROJECTNAME.SizeOfProjectName (section 2.3.4.2.1.6) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.Name.SizeOfProjectName) // 4 bytes
	// APPEND Buffer WITH PROJECTNAME.ProjectName (section 2.3.4.2.1.6) of Storage
	buf = append(buf, p.DirStream.InformationRecord.Name.ProjectName...) // variable
	// APPEND Buffer WITH PROJECTDOCSTRING.Id (section 2.3.4.2.1.7) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0005)) // MUST be 0x0005
	// APPEND Buffer WITH PROJECTDOCSTRING.SizeOfDocString (section 2.3.4.2.1.7) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.DocString.SizeOfDocString) // 4 bytes
	// APPEND Buffer WITH PROJECTDOCSTRING.Reserved (section 2.3.4.2.1.7) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0040)) // MUST be 0x0040
	// APPEND Buffer WITH PROJECTDOCSTRING.SizeOfDocStringUnicode (section 2.3.4.2.1.7) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.DocString.SizeOfDocStringUnicode) // 4 bytes
	// APPEND Buffer WITH PROJECTHELPFILEPATH.Id (section 2.3.4.2.1.8) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0006)) // MUST be 0x0006
	// APPEND Buffer WITH PROJECTHELPFILEPATH.SizeOfHelpFile1 (section 2.3.4.2.1.8) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.HelpFilePath.SizeOfHelpFile1) // 4 bytes
	// APPEND Buffer WITH PROJECTHELPFILEPATH.Reserved (section 2.3.4.2.1.8) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x003d)) // MUST be 0x003D
	// APPEND Buffer WITH PROJECTHELPFILEPATH.SizeOfHelpFile2 (section 2.3.4.2.1.8) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.HelpFilePath.SizeOfHelpFile2) // 4 bytes
	// APPEND Buffer WITH PROJECTHELPCONTEXT.Id (section 2.3.4.2.1.9) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0007)) // MUST be 0x0007
	// APPEND Buffer WITH PROJECTHELPCONTEXT.Size (section 2.3.4.2.1.9) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000004)) // MUST be 0x00000004
	// APPEND Buffer WITH PROJECTLIBFLAGS.Id (section 2.3.4.2.1.10) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0008)) // MUST be 0x0008
	// APPEND Buffer WITH PROJECTLIBFLAGS.Size (section 2.3.4.2.1.10) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000004)) // MUST be 0x00000004
	// APPEND Buffer WITH PROJECTLIBFLAGS.ProjectLibFlags (section 2.3.4.2.1.10) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
	// APPEND Buffer WITH PROJECTVERSION.Id (section 2.3.4.2.1.11) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0009)) // MUST be 0x0009
	// APPEND Buffer WITH PROJECTVERSION.Reserved (section 2.3.4.2.1.11) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000004)) // MUST be 0x00000004
	// APPEND Buffer WITH PROJECTVERSION.VersionMajor (section 2.3.4.2.1.11) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.Version.VersionMajor) // 4 bytes
	// APPEND Buffer WITH PROJECTVERSION.VersionMinor (section 2.3.4.2.1.11) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.Version.VersionMinor) // 2 bytes
	// APPEND Buffer WITH PROJECTCONSTANTS.Id (section 2.3.4.2.1.12) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x000c)) // MUST be 0x000c
	// APPEND Buffer WITH PROJECTCONSTANTS.SizeOfConstants (section 2.3.4.2.1.12) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.Constants.SizeOfConstants) // 4 bytes
	// APPEND Buffer WITH PROJECTCONSTANTS.Constants (section 2.3.4.2.1.12) of Storage
	buf = append(buf, p.DirStream.InformationRecord.Constants.Constants...) // variable
	// APPEND Buffer WITH PROJECTCONSTANTS.Reserved (section 2.3.4.2.1.12) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x003c)) // MUST be 0x003c
	// APPEND Buffer WITH PROJECTCONSTANTS.SizeOfConstantsUnicode (section 2.3.4.2.1.12) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, p.DirStream.InformationRecord.Constants.SizeOfConstantsUnicode) // 4 bytes
	// APPEND Buffer WITH PROJECTCONSTANTS.ConstantsUnicode (section 2.3.4.2.1.12) of Storage
	buf = append(buf, p.DirStream.InformationRecord.Constants.ConstantsUnicode...) // variable

	// FOR EACH REFERENCE (section 2.3.4.2.2.1) IN PROJECTREFERENCES.ReferenceArray (section 2.3.4.2.2) of Storage
	for _, ref := range p.DirStream.ReferencesRecord.ReferenceArray {
		// APPEND Buffer WITH REFERENCENAME.Id (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0016)) // MUST be 0x0016
		// APPEND Buffer WITH REFERENCENAME.SizeOfName (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, ref.NameRecord.SizeOfName) // 4 bytes
		// APPEND Buffer WITH REFERENCENAME.Name (section 2.3.4.2.2.2)
		buf = append(buf, ref.NameRecord.Name...) // variable
		// APPEND Buffer WITH REFERENCENAME.Reserved (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x003e)) // MUST be 0x003e
		// APPEND Buffer WITH REFERENCENAME.SizeOfNameUnicode (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, ref.NameRecord.SizeOfNameUnicode) // 4 bytes
		// APPEND Buffer WITH REFERENCENAME.NameUnicode (section 2.3.4.2.2.2)
		buf = append(buf, ref.NameRecord.NameUnicode...) // variable

		if ref.ControlReference != nil { // IF REFERENCE.ReferenceRecord.Id = 0x002F THEN
			// APPEND Buffer with REFERENCE.ReferenceControl.Id (section 2.3.4.2.2.3)
			buf = writeControlReference(buf, ref.ControlReference) // 4 bytes
		} else if ref.OriginalReference != nil { // ELSE IF REFERENCE.ReferenceRecord.Id = 0x0033 THEN
			// APPEND Buffer with REFERENCE.ReferenceOriginal.Id (section 2.3.4.2.2.4)
			buf = writeOriginalReference(buf, ref.OriginalReference) // variable
		} else if ref.RegisteredReference != nil { // ELSE IF REFERENCE.ReferenceRecord.Id = 0x000D THEN
			// APPEND Buffer with REFERENCE.ReferenceRegistered.Id (section 2.3.4.2.2.5)
			buf = writeRegisteredReference(buf, ref.RegisteredReference) // MUST be 0x0000
		} else if ref.ProjectReference != nil { // ELSE IF REFERENCE.ReferenceRecord.Id = 0x000E THEN
			// APPEND Buffer with REFERENCE.ReferenceProject.Id (section 2.3.4.2.2.6)
			buf = writeProjectReference(buf, ref.ProjectReference) // 2 bytes
		}
	}
	// APPEND Buffer WITH PROJECTMODULES.Id (section 2.3.4.2.3) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x000f)) // MUST be 0x000f
	// APPEND Buffer WITH PROJECTMODULES.Size (section 2.3.4.2.3) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000002)) // MUST be 0x00000002
	// APPEND Buffer WITH PROJECTCOOKIE.Id (section 2.3.4.2.3.1) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0013)) // MUST be 0x0013
	// APPEND Buffer WITH PROJECTCOOKIE.Size (section 2.3.4.2.3.1) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000002)) // MUST be 0x00000002

	var defaultAttributesV3 = []string{ // DEFINE DefaultAttributes AS array of constant char array
		"Attribute VB_Base = \"0{00020820-0000-0000-C000-000000000046}\"",
		"Attribute VB_GlobalNameSpace = False",
		"Attribute VB_Creatable = False",
		"Attribute VB_PredeclaredId = True",
		"Attribute VB_Exposed = True",
		"Attribute VB_TemplateDerived = False",
		"Attribute VB_Customizable = True",
	}

	// FOR EACH MODULE (section 2.3.4.2.3.2) IN PROJECTMODULES.Modules (section 2.3.4.2.3) of Storage
	for _, m := range p.DirStream.ModulesRecord.Modules {
		if m.TypeRecord.Id == 0x0021 { // IF MODULE.TypeRecord.Id = 0x21 THEN
			// APPEND Buffer WITH MODULE.TypeRecord.Id (section 2.3.4.2.3.2.8)
			buf, _ = binary.Append(buf, binary.LittleEndian, m.TypeRecord.Id) // 2 bytes
			// APPEND Buffer WITH MODULE.TypeRecord.Reserved (section 2.3.4.2.3.2.8)
			buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
		}
		if m.ReadOnlyRecord != nil { // IF MODULE.ReadOnlyRecord exists THEN
			// APPEND Buffer WITH MODULE.ReadOnlyRecord.Id (section 2.3.4.2.3.2.9)
			buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0025)) // MUST be 0x0025
			// APPEND Buffer WITH MODULE.ReadOnlyRecord.Reserved (section 2.3.4.2.3.2.9)
			buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
		}
		if m.PrivateRecord != nil { // IF MODULE.PrivateRecord exists THEN
			// APPEND Buffer WITH MODULE.PrivateRecord.Id (section 2.3.4.2.3.2.10)
			buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0028)) // MUST be 0x0028
			// APPEND Buffer WITH MODULE.PrivateRecord.Reserved (section 2.3.4.2.3.2.10)
			buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
		}
		// Get stream
		moduleName, _ := util.ConvertFromCodepageToUtf8(m.NameRecord.ModuleName, p.DirStream.InformationRecord.CodePage.CodePage)
		ms := p.ModuleStream.GetModule(moduleName)
		if ms == nil {
			panic(fmt.Sprintf("Unknown module: %s", moduleName))
		}

		vbaString := string(ms.SourceCode)
		lines := parseModuleV3([]byte(vbaString))

		hashModuleNameFlag := false // DEFINE HashModuleNameFlag AS bool
		for _, lineBytes := range lines {
			line := string(lineBytes)
			if !strings.HasPrefix(strings.ToLower(line), "attribute") { // Line NOT start with “attribute” when ignoring case THEN
				hashModuleNameFlag = true       // SET HashModuleNameFlag TO true
				buf = append(buf, lineBytes...) // APPEND Buffer WITH Line
				buf = append(buf, byte(0x0a))   // APPEND Buffer WITH LF
			} else if strings.HasPrefix(strings.ToLower(line), "attribute vb_name = ") { // Line starts with “Attribute VB_Name = ” when ignoring case THEN
				continue
			} else if !slices.Contains(defaultAttributesV3, line) { // Line not same with any one of DefaultAttributes THEN
				hashModuleNameFlag = true       // SET HashModuleNameFlag TO true
				buf = append(buf, lineBytes...) // APPEND Buffer WITH Line
				buf = append(buf, byte(0x0a))   // APPEND Buffer WITH LF
			}
		}
		if hashModuleNameFlag { // IF HashModuleNameFlag IS true
			if len(m.NameUnicodeRecord.ModuleNameUnicode) > 0 { // IF exist MODULE.NameUnicodeRecord.ModuleNameUnicode
				// APPEND Buffer WITH MODULE.NameUnicodeRecord.ModuleNameUnicode (section 2.3.4.2.3.2.2)
				buf = append(buf, m.NameUnicodeRecord.ModuleNameUnicode...) // variable
			} else if len(m.NameRecord.ModuleName) > 0 { // ELSE IF exist MODULE.NameRecord.ModuleName
				// APPEND Buffer WITH MODULE.NameRecord.ModuleName (section 2.3.4.2.3.2.1)
				buf = append(buf, m.NameRecord.ModuleName...) // variable
			}
			buf = append(buf, byte(0x0a)) // APPEND Buffer WITH LF
		}
	}
	// APPEND Buffer WITH Terminator (section 2.3.4.2) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0010)) // MUST be 0x0010
	// APPEND Buffer WITH Reserved (section 2.3.4.2) of Storage
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
	return buf
}

func writeControlReference(buf []byte, ref *dirstream.ReferenceControl) []byte {
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x002f)) // MUST be 0x002f
	// APPEND Buffer with REFERENCE.ReferenceControl.SizeOfLibidTwiddled (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.SizeOfLibidTwiddled) // 4 bytes
	// APPEND Buffer with REFERENCE.ReferenceControl.LibidTwiddled (section 2.3.4.2.2.3)
	buf = append(buf, ref.LibidTwiddled...) // variable
	// APPEND Buffer with REFERENCE.ReferenceControl.Reserved1 (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
	// APPEND Buffer with REFERENCE.ReferenceControl.Reserved2 (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0000)) // MUST be 0x0000
	// IF exists REFERENCE.ReferenceControl.NameRecordExtended (section 2.3.4.2.2.2) THEN
	if ref.NameRecordExtended != nil {
		// APPEND Buffer WITH REFERENCE.ReferenceControl.NameRecordExtended.Id (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0016)) // MUST be 0x0016
		// APPEND Buffer WITH REFERENCE.ReferenceControl.NameRecordExtended.Size (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, ref.NameRecordExtended.SizeOfName) // 4 bytes
		// APPEND Buffer WITH REFERENCE.ReferenceControl.NameRecordExtended.Name (section 2.3.4.2.2.2)
		buf = append(buf, ref.NameRecordExtended.Name...) // variable
	}
	// IF exists REFERENCE.ReferenceControl.NameRecordExtended.Reserved (section 2.3.4.2.2.2) THEN
	if ref.NameRecordExtended.Reserved > 0 {
		// APPEND Buffer WITH REFERENCE.ReferenceControl.NameRecordExtended.Reserved (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x003e)) // MUST be 0x003e
		// APPEND Buffer WITH REFERENCE.ReferenceControl.NameRecordExtended.SizeOfNameUnicode (section 2.3.4.2.2.2)
		buf, _ = binary.Append(buf, binary.LittleEndian, ref.NameRecordExtended.SizeOfNameUnicode) // 4 bytes
		// APPEND Buffer WITH REFERENCE.ReferenceControl.NameRecordExtended.NameUnicode (section 2.3.4.2.2.2)
		buf = append(buf, ref.NameRecordExtended.NameUnicode...) // variable
	}
	// APPEND Buffer with REFERENCE.ReferenceControl.Reserved3 (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0030)) // MUST be 0x0030
	// APPEND Buffer with REFERENCE.ReferenceControl.SizeOfLibidExtended (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.SizeOfLibidExtended) // 4 bytes
	// APPEND Buffer with REFERENCE.ReferenceControl.LibidExtended (section 2.3.4.2.2.3)
	buf = append(buf, ref.LibidExtended...) // variable
	// APPEND Buffer with REFERENCE.ReferenceControl.Reserved4 (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
	// APPEND Buffer with REFERENCE.ReferenceControl.Reserved5 (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0000)) // MUST be 0x0000
	// APPEND Buffer with REFERENCE.ReferenceControl.OriginalTypeLib (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.OriginalTypeLib) // 16 bytes
	// APPEND Buffer with REFERENCE.ReferenceControl.Cookie (section 2.3.4.2.2.3)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.Cookie)
	return buf
}

func writeOriginalReference(buf []byte, ref *dirstream.ReferenceOriginal) []byte {
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0033)) // MUST be 0x0033
	// APPEND Buffer with REFERENCE.ReferenceOriginal.SizeOfLibidOriginal (section 2.3.4.2.2.4)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.SizeOfLibidOriginal) // 4 bytes
	// APPEND Buffer with REFERENCE.ReferenceOriginal.LibidOriginal (section 2.3.4.2.2.4)
	buf = append(buf, ref.LibidOriginal...)
	// APPEND Buffer with ControlReference, if it exists
	if ref.ReferenceRecord != nil {
		buf = writeControlReference(buf, ref.ReferenceRecord)
	}
	return buf
}

func writeRegisteredReference(buf []byte, ref *dirstream.ReferenceRegistered) []byte {
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x000d)) // MUST be 0x000d
	// APPEND Buffer with REFERENCE.ReferenceRegistered.SizeOfLibid (section 2.3.4.2.2.5)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.SizeOfLibid) // 4 bytes
	// APPEND Buffer with REFERENCE.ReferenceRegistered.Libid (section 2.3.4.2.2.5)
	buf = append(buf, util.GetFixedWidthString16(ref.Libid)...) // variable
	// APPEND Buffer with REFERENCE.ReferenceRegistered.Reserved1 (section 2.3.4.2.2.5)
	buf, _ = binary.Append(buf, binary.LittleEndian, int32(0x00000000)) // MUST be 0x00000000
	// APPEND Buffer with REFERENCE.ReferenceRegistered.Reserved2 (section 2.3.4.2.2.5)
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x0000))
	return buf
}

func writeProjectReference(buf []byte, ref *dirstream.ReferenceProject) []byte {
	buf, _ = binary.Append(buf, binary.LittleEndian, int16(0x000e)) // MUST be 0x000e
	// APPEND Buffer with REFERENCE.ReferenceProject.SizeOfLibidAbsolute (section 2.3.4.2.2.6)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.SizeOfLibidAbsolute) // 4 bytes
	// APPEND Buffer with REFERENCE.ReferenceProject.LibidAbsolute (section 2.3.4.2.2.6)
	buf = append(buf, ref.LibidAbsolute...) // variable
	// APPEND Buffer with REFERENCE.ReferenceProject.SizeOfLibidRelative (section 2.3.4.2.2.6)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.SizeOfLibidRelative) // 4 bytes
	// APPEND Buffer with REFERENCE.ReferenceProject.LibidRelative(section 2.3.4.2.2.6)
	buf = append(buf, ref.LibidRelative...) // variable
	// APPEND Buffer with REFERENCE.ReferenceProject.MajorVersion(section 2.3.4.2.2.6)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.MajorVersion) // 4 bytes
	// APPEND Buffer with REFERENCE.ReferenceProject.MinorVersion (section 2.3.4.2.2.6)
	buf, _ = binary.Append(buf, binary.LittleEndian, ref.MinorVersion)
	return buf
}

// 2.4.2.6 Project Normalized Data
func projectNormalizedData(p *VbaProject) []byte {
	buf := bytes.Buffer{}
	// FOR EACH property in ProjectProperties (section 2.3.1.1)
	for _, prop := range p.ProjectStream.MainProperties {
		if prop.Key == "BaseClass" { // IF property is ProjectDesignerModule THEN
			// APPEND Buffer WITH output of NormalizeDesignerStorage(ProjectDesignerModule) (section 2.4.2.2)
			mod := p.ModuleStream.GetModule(prop.Value)
			buf.Write(normalizeDesignerStorage(mod))
		}
		// IF property NOT is ProjectId (section 2.3.1.2) OR ProjectDocModule (section 2.3.1.4)
		// OR ProjectProtectionState (section 2.3.1.15) OR ProjectPassword (section 2.3.1.16)
		// OR ProjectVisibilityState (section 2.3.1.17) THEN
		if !slices.Contains([]string{"ID", "Document", "CMG", "DPB", "GC"}, prop.Key) && !strings.HasPrefix(prop.Key, "&H") {
			// APPEND Buffer WITH property name
			// APPEND Buffer WITH property value
			buf.WriteString(fmt.Sprintf("%s%s", prop.Key, prop.Value))
		}
	}
	// IF exist string “[Host Extender Info]” THEN
	if strings.Contains(p.ProjectStream.Raw, "Host Extender Info") {
		// APPEND Buffer WITH the string “Host Extender Info”
		buf.WriteString("Host Extender Info")
		for _, prop := range p.ProjectStream.HostExtenderProperties {
			if strings.HasPrefix(prop.Key, "&H") { // is ExtenderIndex, HEXINT32
				// APPEND Buffer WITH HostExtenderRef without NWLN (section 2.3.1.18)
				buf.WriteString(prop.Line)
			}
		}
	}
	return buf.Bytes()
}

func parseModuleV3(text []byte) [][]byte {
	var lines [][]byte
	var textBuffer []byte
	var previousChar byte

	for _, char := range text {
		if char == 0x0a || char == 0x0d {
			if previousChar == 0x0d {
				lines = append(lines, textBuffer)
				textBuffer = []byte{}
			}
		} else {
			textBuffer = append(textBuffer, char)
		}
		previousChar = char
	}
	return lines
}
