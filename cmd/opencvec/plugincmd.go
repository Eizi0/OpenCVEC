package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Eizi0/OpenCVEC/internal/plugin"
)

const pluginUsage = `Outils des plugins :
  opencvec plugin keygen <préfixe>          crée <préfixe>.pub et <préfixe>.key (clé privée : à garder secrète)
  opencvec plugin lint <plugin.yaml>...     vérifie le format sans rien exécuter
  opencvec plugin sign <clé.key> <plugin.yaml>...
                                            écrit <plugin.yaml>.sig à côté de chaque plugin
  opencvec plugin verify <clé.pub> <plugin.yaml>...
  opencvec plugin index <dossier>           (re)génère <dossier>/index.json pour un dépôt de plugins
`

// Index est le catalogue d'un dépôt de plugins (index.json).
type Index struct {
	Publisher string       `json:"publisher"`
	PublicKey string       `json:"public_key"`
	Plugins   []IndexEntry `json:"plugins"`
}

// IndexEntry décrit un plugin du dépôt.
type IndexEntry struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	CVEs        []string `json:"cves"`
	Mode        string   `json:"mode"`
	Product     string   `json:"product"`
	Description string   `json:"description"`
	File        string   `json:"file"`
	Signature   string   `json:"signature"`
	SHA256      string   `json:"sha256"`
}

func pluginCmd(args []string) error {
	if len(args) == 0 {
		fmt.Print(pluginUsage)
		return nil
	}
	switch args[0] {
	case "keygen":
		if len(args) != 2 {
			return errors.New("usage : opencvec plugin keygen <préfixe>")
		}
		pub, key, err := plugin.GenerateKey()
		if err != nil {
			return err
		}
		if _, err := os.Stat(args[1] + ".key"); err == nil {
			return fmt.Errorf("%s.key existe déjà : refus d'écraser une clé", args[1])
		}
		if err := os.WriteFile(args[1]+".key", []byte(key+"\n"), 0o600); err != nil {
			return err
		}
		if err := os.WriteFile(args[1]+".pub", []byte(pub+"\n"), 0o644); err != nil {
			return err
		}
		pk, _ := plugin.ParsePublicKey(pub)
		fmt.Printf("Clé %s créée.\nPublique : %s.pub (à diffuser)\nPrivée   : %s.key (à garder secrète, sauvegardée hors du dépôt)\n", plugin.KeyID(pk), args[1], args[1])
		return nil
	case "lint":
		failed := false
		for _, f := range args[1:] {
			b, err := os.ReadFile(f)
			if err == nil {
				_, err = plugin.Parse(b)
			}
			if err != nil {
				failed = true
				fmt.Printf("ÉCHEC %s : %v\n", f, err)
			} else {
				fmt.Printf("OK    %s\n", f)
			}
		}
		if failed {
			return errors.New("plugin(s) invalide(s)")
		}
		return nil
	case "sign":
		if len(args) < 3 {
			return errors.New("usage : opencvec plugin sign <clé.key> <plugin.yaml>...")
		}
		kb, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		key, err := plugin.ParsePrivateKey(string(kb))
		if err != nil {
			return err
		}
		for _, f := range args[2:] {
			b, err := os.ReadFile(f)
			if err != nil {
				return err
			}
			if _, err := plugin.Parse(b); err != nil {
				return fmt.Errorf("%s : refus de signer un plugin invalide : %w", f, err)
			}
			if err := os.WriteFile(f+".sig", []byte(plugin.Sign(key, b)), 0o644); err != nil {
				return err
			}
			fmt.Printf("signé : %s.sig\n", f)
		}
		return nil
	case "verify":
		if len(args) < 3 {
			return errors.New("usage : opencvec plugin verify <clé.pub> <plugin.yaml>...")
		}
		pb, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		pub, err := plugin.ParsePublicKey(string(pb))
		if err != nil {
			return err
		}
		for _, f := range args[2:] {
			b, _ := os.ReadFile(f)
			sig, _ := os.ReadFile(f + ".sig")
			if _, err := plugin.Verify(b, string(sig), []plugin.Publisher{{Name: "clé fournie", Key: pub}}); err != nil {
				return fmt.Errorf("%s : %w", f, err)
			}
			fmt.Printf("OK    %s\n", f)
		}
		return nil
	case "index":
		if len(args) != 2 {
			return errors.New("usage : opencvec plugin index <dossier>")
		}
		return writeIndex(args[1])
	}
	fmt.Print(pluginUsage)
	return errors.New("sous-commande inconnue")
}

func writeIndex(dir string) error {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	idx := Index{Publisher: plugin.OfficialName, PublicKey: strings.TrimSpace(plugin.OfficialPublicKey)}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		p, err := plugin.Parse(b)
		if err != nil {
			return fmt.Errorf("%s : %w", f, err)
		}
		if _, err := os.Stat(f + ".sig"); err != nil {
			return fmt.Errorf("%s : signature absente (opencvec plugin sign)", f)
		}
		base := filepath.Base(f)
		idx.Plugins = append(idx.Plugins, IndexEntry{ID: p.ID, Name: p.Name, Version: p.Version, CVEs: p.CVEs, Mode: p.Mode,
			Product: p.Product, Description: p.Description, File: base, Signature: base + ".sig", SHA256: plugin.SHA256(b)})
	}
	b, _ := json.MarshalIndent(idx, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "index.json"), append(b, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("index.json : %d plugin(s)\n", len(idx.Plugins))
	return nil
}
