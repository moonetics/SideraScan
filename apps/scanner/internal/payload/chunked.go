package payload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/moonetics/SideraScan/apps/scanner/internal/contract"
)

const DefaultMaxSectionBytes = 4 * 1024 * 1024

type UploadSection struct {
	Name  string
	Items []any
}

type SectionChunk struct {
	Section     string
	Items       []any
	ChunkIndex  int
	ChunkCount  int
	TotalItems  int
	PayloadHash string
}

func CoreUploadRequest(input contract.UploadResultsRequest, sectionNames []string) contract.UploadResultsRequest {
	core := input
	core.ProcessTimeline = nil
	core.ExploreFiles = nil
	core.Utilities = nil
	core.WindowsItems = nil
	core.LauncherProfiles = nil
	core.ClientModAssets = nil
	core.ProcessTimes = nil
	core.FileLogs = nil
	core.LoadedModules = nil
	core.ProcessHandles = nil
	core.Services = nil
	core.Drivers = nil
	core.PersistenceItems = nil
	core.EventLogs = nil
	core.DefenderEvents = nil
	core.ExecutionArtifacts = nil
	core.FileTriage = nil
	core.NetworkConnections = nil
	core.DNSCache = nil
	core.HostsEntries = nil
	core.ForensicTimeline = nil
	if core.Integrity == nil {
		core.Integrity = map[string]any{}
	}
	core.Integrity["uploadMode"] = "chunked"
	core.Integrity["sectionUploadPlanned"] = sectionNames
	core.Integrity["sectionUploadStatus"] = map[string]any{}
	return core
}

func UploadSections(input contract.UploadResultsRequest) []UploadSection {
	sections := []UploadSection{}
	addMapSection := func(name string, items []map[string]any) {
		if len(items) > 0 {
			sections = append(sections, UploadSection{Name: name, Items: mapsToAny(items)})
		}
	}
	addAnySection := func(name string, items []any) {
		if len(items) > 0 {
			sections = append(sections, UploadSection{Name: name, Items: items})
		}
	}

	addMapSection("processTimeline", input.ProcessTimeline)
	addMapSection("exploreFiles", input.ExploreFiles)
	addMapSection("utilities", input.Utilities)
	addMapSection("windowsItems", input.WindowsItems)
	addAnySection("launcherProfiles", typedToAny(input.LauncherProfiles))
	addAnySection("clientModAssets", typedToAny(input.ClientModAssets))
	addAnySection("processTimes", typedToAny(input.ProcessTimes))
	addAnySection("fileLogs", typedToAny(input.FileLogs))
	addMapSection("loadedModules", input.LoadedModules)
	addMapSection("processHandles", input.ProcessHandles)
	addMapSection("services", input.Services)
	addMapSection("drivers", input.Drivers)
	addMapSection("persistenceItems", input.PersistenceItems)
	addMapSection("eventLogs", input.EventLogs)
	addMapSection("defenderEvents", input.DefenderEvents)
	addMapSection("executionArtifacts", input.ExecutionArtifacts)
	addMapSection("fileTriage", input.FileTriage)
	addMapSection("networkConnections", input.NetworkConnections)
	addMapSection("dnsCache", input.DNSCache)
	addMapSection("hostsEntries", input.HostsEntries)
	addMapSection("forensicTimeline", input.ForensicTimeline)
	return sections
}

func SplitSection(section UploadSection, maxBytes int) []SectionChunk {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxSectionBytes
	}
	if len(section.Items) == 0 {
		return nil
	}

	groups := [][]any{}
	current := []any{}
	for _, item := range section.Items {
		test := append(append([]any{}, current...), item)
		if len(current) > 0 && sectionItemsSize(test) > maxBytes {
			groups = append(groups, current)
			current = []any{item}
			continue
		}
		current = test
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}

	chunks := make([]SectionChunk, 0, len(groups))
	for index, items := range groups {
		chunks = append(chunks, SectionChunk{
			Section:     section.Name,
			Items:       items,
			ChunkIndex:  index,
			ChunkCount:  len(groups),
			TotalItems:  len(section.Items),
			PayloadHash: hashItems(items),
		})
	}
	return chunks
}

func SectionNames(sections []UploadSection) []string {
	names := make([]string, 0, len(sections))
	for _, section := range sections {
		names = append(names, section.Name)
	}
	return names
}

func sectionItemsSize(items []any) int {
	bytes, err := json.Marshal(items)
	if err != nil {
		return 0
	}
	return len(bytes)
}

func hashItems(items []any) string {
	bytes, err := json.Marshal(items)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(bytes)
	return hex.EncodeToString(sum[:])
}

func mapsToAny(items []map[string]any) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

func typedToAny[T any](items []T) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}
