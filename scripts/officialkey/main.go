// Affiche la clé publique officielle intégrée (utilisé par la CI pour vérifier les plugins du dépôt).
package main

import (
	"fmt"

	"github.com/Eizi0/OpenCVEC/internal/plugin"
)

func main() { fmt.Println(plugin.OfficialPublicKey) }
