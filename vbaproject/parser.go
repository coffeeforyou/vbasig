package vbaproject

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"

	"github.com/coffeeforyou/vbasig/vbacompression"
	"github.com/coffeeforyou/vbasig/vbaproject/dirstream"
	"github.com/coffeeforyou/vbasig/vbaproject/modulestream"
	"github.com/coffeeforyou/vbasig/vbaproject/projectstream"
	"github.com/richardlehane/mscfb"
)

func ParseVbaProject(file io.ReaderAt) (*VbaProject, error) {
	// Create new reader for OLE file system
	doc, err := mscfb.New(file)
	if err != nil {
		log.Fatal(err)
	}
	// Initialize VBA project
	vbap := VbaProject{}
	streams := make(map[string]*mscfb.File)
	// First iteration over streams to read the relevant information (name, offset) to extract the VBA modules
	// and create map with streams for convenient access
	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		if entry.Size > 0 {
			fullName := fmt.Sprintf("%s/%s", strings.Join(entry.Path, "/"), entry.Name)
			if _, ok := streams[fullName]; ok {
				panic("duplicate stream name")
			}
			streams[fullName] = entry
		}
		if entry.Name == "dir" {
			compressedContainerBytes, _ := io.ReadAll(entry)
			db, _, err := vbacompression.DecompressContainer(compressedContainerBytes)
			if err != nil {
				return nil, err
			}
			vbaProjectReader := bytes.NewReader(db)
			vbap.DirStream, err = dirstream.ParseDirStream(vbaProjectReader)
			if err != nil {
				return nil, err
			}
		}

		if entry.Name == "PROJECT" {
			b, err := io.ReadAll(entry)
			if err != nil {
				return nil, err
			}
			vbap.ProjectStream = projectstream.ParseProjectStream(string(b))
		}
	}

	// Iteration over modules to read all VBA modules
	mswo := vbap.GetModulesWithOffset()
	for _, mwo := range mswo {
		if entry, ok := streams[fmt.Sprintf("VBA/%s", mwo.Name)]; ok {
			moduleStreamBytes, err := io.ReadAll(entry)
			if err != nil {
				return nil, err
			}
			moduleStreamBytesEff := moduleStreamBytes[mwo.Offset:]
			tmp, err := modulestream.ParseModuleStream(moduleStreamBytesEff)
			tmp.Name = mwo.Name
			tmp.Raw = moduleStreamBytes
			if err != nil {
				return nil, err
			}
			vbap.ModuleStream.Modules = append(vbap.ModuleStream.Modules, tmp)
		}
	}

	// Third iteration of streams to add VBFrame information
	doc, _ = mscfb.New(file)
	for entry, err := doc.Next(); err == nil; entry, err = doc.Next() {
		if entry.Size == 0 {
			continue
		}
		for _, m := range vbap.ModuleStream.Modules {
			if slices.Contains(entry.Path, m.Name) {
				csb, err := io.ReadAll(entry)
				if err != nil {
					return nil, err
				}
				m.ChildStreams = append(m.ChildStreams, modulestream.ChildStream{Raw: csb, Name: entry.Name, Path: entry.Path})
			}
		}
	}
	return &vbap, nil
}
