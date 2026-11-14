// Package plugins embarque les plugins officiels signés : ils sont préinstallés au premier
// démarrage, y compris sur une instance sans accès à Internet.
package plugins

import "embed"

// FS contient les plugins officiels (*.yaml), leurs signatures (*.yaml.sig) et index.json.
//
//go:embed *.yaml *.yaml.sig index.json
var FS embed.FS
