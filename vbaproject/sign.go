package vbaproject

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/coffeeforyou/vbasig/util"
	"github.com/coffeeforyou/vbasig/vbasigfile"
)

func SignVbaProject(officeFilePath string, certPath string, keyPath string, caPath string, so SignOptions) {
	// Try to load provided key material
	signCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	util.TerminateIfErr(err)
	var caCerts []*x509.Certificate
	if caPath != "" {
		caCert, err := util.LoadPemCertificate(caPath)
		util.TerminateIfErr(err)
		caCerts = append(caCerts, caCert)
	}
	// Open original file
	zipReader, err := zip.OpenReader(officeFilePath)
	util.TerminateIfErr(err)
	defer zipReader.Close()

	// Type of Office file
	var pathToVba, newFileExt string
	switch filepath.Ext(officeFilePath) {
	case ".docm":
		pathToVba = "word"
		newFileExt = "docm"
	case ".xlsm":
		pathToVba = "xl"
		newFileExt = "xlsm"
	case ".pptm":
		pathToVba = "ppt"
		newFileExt = "pptm"
	default:
		util.TerminateIfErr(fmt.Errorf("unknown file extension: %s", filepath.Ext(officeFilePath)))
	}

	// Load VBA project
	vbaProjectFile, err := zipReader.Open(fmt.Sprintf("%s/vbaProject.bin", pathToVba))
	util.TerminateIfErr(err)
	// Read and decompress VBA project
	vbaProjectFileBytes, err := io.ReadAll(vbaProjectFile)
	util.TerminateIfErr(err)
	vbaProjectFileOs := bytes.NewReader(vbaProjectFileBytes)

	// Parse VBA project and generate signatures
	vbaProject, err := ParseVbaProject(vbaProjectFileOs)
	util.TerminateIfErr(err)

	// Base name of new file
	baseName := strings.TrimSuffix(officeFilePath, filepath.Ext(officeFilePath))

	// Create new xlsm/docm file
	zipfile, err := os.Create(fmt.Sprintf("%s-signed.%s", baseName, newFileExt))
	util.TerminateIfErr(err)
	defer zipfile.Close()

	// Zip writer
	zipWriter := zip.NewWriter(zipfile)
	defer zipWriter.Close()

	// GENERATE V1 SIGNATURE
	if so.IncludeV1 {
		signatureBytes, err := GetProjectSignatureV1(vbaProject, &signCert, caCerts)
		util.TerminateIfErr(err)
		signatureFile, err := vbasigfile.NewDigSigInfoSerialized(signatureBytes, *signCert.Leaf)
		util.TerminateIfErr(err)
		// New signature file to add to the zip
		sigFile, err := zipWriter.Create(fmt.Sprintf("%s/vbaProjectSignature.bin", pathToVba))
		util.TerminateIfErr(err)
		// Write signature to ZIP file
		_, err = sigFile.Write(signatureFile.Serialize())
		util.TerminateIfErr(err)
	}

	// GENERATE AGILE SIGNATURE
	if so.IncludeAgile {
		signatureBytesAgile, err := GetProjectSignatureAgile(vbaProject, &signCert, caCerts)
		util.TerminateIfErr(err)
		signatureFileAgile, err := vbasigfile.NewDigSigInfoSerialized(signatureBytesAgile, *signCert.Leaf)
		util.TerminateIfErr(err)
		// New signature file to add to the zip
		sigFileAgile, err := zipWriter.Create(fmt.Sprintf("%s/vbaProjectSignatureAgile.bin", pathToVba))
		util.TerminateIfErr(err)
		// Write signature to ZIP file
		_, err = sigFileAgile.Write(signatureFileAgile.Serialize())
		util.TerminateIfErr(err)
	}

	// GENERATE V3 SIGNATURE
	if so.IncludeV3 {
		signatureBytesV3, err := GetProjectSignatureV3(vbaProject, &signCert, caCerts)
		util.TerminateIfErr(err)
		signatureFileV3, err := vbasigfile.NewDigSigInfoSerialized(signatureBytesV3, *signCert.Leaf)
		util.TerminateIfErr(err)
		// New signature file to add to the zip
		sigFileV3, err := zipWriter.Create(fmt.Sprintf("%s/vbaProjectSignatureV3.bin", pathToVba))
		util.TerminateIfErr(err)
		// Write signature to ZIP file
		_, err = sigFileV3.Write(signatureFileV3.Serialize())
		util.TerminateIfErr(err)
	}

	// Read relationships to ensure that VBA rels are present
	relFileOrig, err := zipReader.Open(fmt.Sprintf("%s/_rels/vbaProject.bin.rels", pathToVba))
	var relFileBytes []byte = []byte(DefaultRels)
	if err == nil {
		relFileBytes, err = io.ReadAll(relFileOrig)
		util.TerminateIfErr(err)
	}
	// Update XML structure if needed
	relFileBytes, err = AddRels(relFileBytes, pathToVba, so)
	util.TerminateIfErr(err)
	// Write updated content types to ZIP
	relFile, err := zipWriter.Create(fmt.Sprintf("%s/_rels/vbaProject.bin.rels", pathToVba))
	util.TerminateIfErr(err)
	_, err = relFile.Write(relFileBytes)
	util.TerminateIfErr(err)

	// Read content types to ensure that VBA types are present
	ctFileOrig, err := zipReader.Open("[Content_Types].xml")
	util.TerminateIfErr(err)
	// Read content types file
	ctFileBytes, err := io.ReadAll(ctFileOrig)
	util.TerminateIfErr(err)
	// Update XML structure if needed
	ctFileBytes, err = AddContentTypes(ctFileBytes, pathToVba, so)
	util.TerminateIfErr(err)
	// Write updated content types to ZIP
	ctFile, err := zipWriter.Create("[Content_Types].xml")
	util.TerminateIfErr(err)
	_, err = ctFile.Write(ctFileBytes)
	util.TerminateIfErr(err)

	for _, entry := range zipReader.File {
		if strings.HasSuffix(entry.Name, "vbaProjectSignature.bin") ||
			strings.HasSuffix(entry.Name, "vbaProjectSignatureAgile.bin") ||
			strings.HasSuffix(entry.Name, "vbaProjectSignatureV3.bin") ||
			strings.HasSuffix(entry.Name, "bin.rels") ||
			strings.HasSuffix(entry.Name, "[Content_Types].xml") {
			continue
		}
		writer, err := zipWriter.Create(entry.Name)
		util.TerminateIfErr(err)
		reader, err := entry.Open()
		util.TerminateIfErr(err)
		_, err = io.Copy(writer, reader)
		util.TerminateIfErr(err)
		reader.Close()
	}
}
