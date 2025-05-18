package projectstream

import "strings"

type ProjectStream struct {
	ID                     string
	ProjectDocModules      []string
	ProjectStdModules      []string
	ProjectDesignerModules []string
	ProjectClassModules    []string
	Name                   string
	HelpContextID          string
	VersionCompatible32    string
	CMG                    string
	DPB                    string
	GC                     string
	MainProperties         []ProjectProperty
	HostExtenderProperties []ProjectProperty
	OtherProperties        []ProjectProperty
	Raw                    string
}

type ProjectProperty struct {
	Key   string
	Value string
	Line  string
}

func ParseProjectStream(input string) ProjectStream {
	var ps ProjectStream
	var section string // to indicate that other section has started
	ps.Raw = input
	lines := strings.Split(input, "\r\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and section headers
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.Trim(parts[1], "\"") // Remove surrounding quotes if any

		// keeping properties as groups
		switch section {
		case "":
			ps.MainProperties = append(ps.MainProperties, ProjectProperty{Key: key, Value: value, Line: line})
		case "Host Extender Info":
			ps.HostExtenderProperties = append(ps.HostExtenderProperties, ProjectProperty{Key: key, Value: value, Line: line})
		default:
			ps.OtherProperties = append(ps.OtherProperties, ProjectProperty{Key: key, Value: value, Line: line})
		}

		// extracting specific values
		switch key {
		case "ID":
			ps.ID = value
		case "Document":
			ps.ProjectDocModules = append(ps.ProjectDocModules, value)
		case "Module":
			ps.ProjectStdModules = append(ps.ProjectStdModules, value)
		case "BaseClass":
			ps.ProjectDesignerModules = append(ps.ProjectDesignerModules, value)
		case "Class":
			ps.ProjectStdModules = append(ps.ProjectStdModules, value)
		case "Name":
			ps.Name = value
		case "HelpContextID":
			ps.HelpContextID = value
		case "VersionCompatible32":
			ps.VersionCompatible32 = value
		case "CMG":
			ps.CMG = value
		case "DPB":
			ps.DPB = value
		case "GC":
			ps.GC = value
		}
	}
	return ps
}
