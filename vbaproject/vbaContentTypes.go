package vbaproject

import (
	"encoding/xml"
	"fmt"
)

type Types struct {
	XMLName   xml.Name   `xml:"http://schemas.openxmlformats.org/package/2006/content-types Types"`
	Defaults  []Default  `xml:"Default"`
	Overrides []Override `xml:"Override"`
}

type Default struct {
	Extension   string `xml:"Extension,attr"`
	ContentType string `xml:"ContentType,attr"`
}

type Override struct {
	PartName    string `xml:"PartName,attr"`
	ContentType string `xml:"ContentType,attr"`
}

func AddContentTypes(xmlData []byte, path string, so SignOptions) ([]byte, error) {
	// Step 1: Unmarshal XML to struct
	var types Types
	if err := xml.Unmarshal([]byte(xmlData), &types); err != nil {
		return nil, err
	}

	// Step 2: Check the overrides for VBA are present
	if so.IncludeV1 {
		types.updateOverrides(fmt.Sprintf("/%s/vbaProjectSignature.bin", path), "application/vnd.ms-office.vbaProjectSignature")
	}
	if so.IncludeAgile {
		types.updateOverrides(fmt.Sprintf("/%s/vbaProjectSignatureAgile.bin", path), "application/vnd.ms-office.vbaProjectSignatureAgile")
	}
	if so.IncludeV3 {
		types.updateOverrides(fmt.Sprintf("/%s/vbaProjectSignatureV3.bin", path), "application/vnd.ms-office.vbaProjectSignatureV3")
	}

	// Step 3: Marshal struct back to XML
	output, err := xml.MarshalIndent(types, "", "  ")
	if err != nil {
		return nil, err
	}

	// Step 4: Get header back
	output = append([]byte(xml.Header), output...)
	return output, nil
}

func (t *Types) updateOverrides(partName string, contentType string) {
	for _, o := range t.Overrides {
		if o.PartName == partName {
			return
		}
	}
	t.Overrides = append(t.Overrides, Override{
		PartName:    partName,
		ContentType: contentType,
	})
}
