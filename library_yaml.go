package easyfl

import _ "embed"

// Legacy YAML carrier for the base library. Will be removed together with
// library.yaml and the YAML serde in phase 3 of the JSON migration
// (see claude/json_persistence.md). The canonical base library bytes now
// live in library.json (variable baseLibraryDefinitions in library_json.go).

//go:embed library.yaml
var baseLibraryDefinitionsYAML string