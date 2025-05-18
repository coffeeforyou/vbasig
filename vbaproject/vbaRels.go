package vbaproject

import (
	"encoding/xml"
	"fmt"
)

type Relationships struct {
	XMLName       xml.Name        `xml:"http://schemas.openxmlformats.org/package/2006/relationships Relationships"`
	Relationships []*Relationship `xml:"Relationship"`
}

type Relationship struct {
	ID     string `xml:"Id,attr"`
	Type   string `xml:"Type,attr"`
	Target string `xml:"Target,attr"`
}

func AddRels(xmlData []byte, path string, so SignOptions) ([]byte, error) {
	// Step 1: Unmarshal XML to struct
	var relationships Relationships
	if err := xml.Unmarshal([]byte(xmlData), &relationships); err != nil {
		return nil, err
	}

	// Step 2: Check the elements for VBA are present
	if so.IncludeV1 {
		relationships.updateRelationship("vbaProjectSignature.bin", "http://schemas.microsoft.com/office/2006/relationships/vbaProjectSignature")
	}
	if so.IncludeAgile {
		relationships.updateRelationship("vbaProjectSignatureAgile.bin", "http://schemas.microsoft.com/office/2014/relationships/vbaProjectSignatureAgile")
	}
	if so.IncludeV3 {
		relationships.updateRelationship("vbaProjectSignatureV3.bin", "http://schemas.microsoft.com/office/2020/07/relationships/vbaProjectSignatureV3")
	}

	// Step 3: Renumber items to ensure unique ids
	for i, r := range relationships.Relationships {
		r.ID = fmt.Sprintf("rId%d", i+1)
	}

	// Step 3: Marshal struct back to XML
	output, err := xml.MarshalIndent(relationships, "", "  ")
	if err != nil {
		return nil, err
	}

	// Step 4: Get header back
	output = append([]byte(xml.Header), output...)
	return output, nil
}

func (t *Relationships) updateRelationship(target string, relType string) {
	for _, r := range t.Relationships {
		if r.Target == target {
			return
		}
	}
	t.Relationships = append(t.Relationships, &Relationship{
		Target: target,
		Type:   relType,
	})
}

const DefaultRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
</Relationships>`
