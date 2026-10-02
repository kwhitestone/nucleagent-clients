// Package release embeds the reviewed catalog and its pinned verification key.
package release

import _ "embed"

//go:embed catalog.json
var Catalog []byte

//go:embed catalog.pub
var PublicKey string
