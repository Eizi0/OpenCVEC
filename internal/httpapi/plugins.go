package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Eizi0/OpenCVEC/internal/netguard"
	"github.com/Eizi0/OpenCVEC/internal/plugin"
	"github.com/Eizi0/OpenCVEC/internal/settings"
)

type pluginRow struct {
	ID          string    `json:"id"`
	Version     string    `json:"version"`
	Name        string    `json:"name"`
	SHA256      string    `json:"sha256"`
	Publisher   string    `json:"publisher"`
	Signed      bool      `json:"signed"`
	Enabled     bool      `json:"enabled"`
	Source      string    `json:"source"`
	InstalledBy string    `json:"installed_by"`
	InstalledAt time.Time `json:"installed_at"`
	Content     string    `json:"content,omitempty"`
}

func (s *Server) listPlugins(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT p.id, p.version, p.name, p.sha256, p.publisher, p.signed, p.enabled, p.source,
		COALESCE(u.email, ''), p.installed_at, convert_from(p.content, 'UTF8')
		FROM plugins p LEFT JOIN users u ON u.id = p.installed_by ORDER BY p.name`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []pluginRow{}
	for rows.Next() {
		var x pluginRow
		if err := rows.Scan(&x.ID, &x.Version, &x.Name, &x.SHA256, &x.Publisher, &x.Signed, &x.Enabled, &x.Source, &x.InstalledBy, &x.InstalledAt, &x.Content); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, http.StatusOK, out)
}

// fetchPublic télécharge un fichier en HTTPS depuis une adresse publique (dépôt de plugins).
func fetchPublic(ctx context.Context, raw string, max int64) ([]byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("seules les URL https:// sont acceptées")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Header.Set("User-Agent", "OpenCVEC/0.2 (plugins)")
	resp, err := netguard.Policy{}.Client(10 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s : HTTP %d", u.Redacted(), resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("fichier trop volumineux")
	}
	return b, nil
}

type pluginInput struct {
	Content   string `json:"content"`
	Signature string `json:"signature"`
	URL       string `json:"url"`
}

// resolveInput renvoie le contenu et la signature, téléchargés si une URL est fournie (signature : URL + « .sig »).
func (s *Server) resolveInput(ctx context.Context, in pluginInput) ([]byte, string, string, error) {
	if in.URL != "" {
		data, err := fetchPublic(ctx, in.URL, plugin.MaxSize)
		if err != nil {
			return nil, "", "", fmt.Errorf("téléchargement du plugin : %w", err)
		}
		sig, err := fetchPublic(ctx, in.URL+".sig", 4096)
		if err != nil {
			sig = nil // l'absence de signature est signalée par la vérification
		}
		return data, string(sig), in.URL, nil
	}
	if strings.TrimSpace(in.Content) == "" {
		return nil, "", "", errors.New("fournissez le fichier du plugin ou son URL")
	}
	return []byte(in.Content), in.Signature, "import manuel", nil
}

type pluginPreview struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Version            string   `json:"version"`
	CVEs               []string `json:"cves"`
	Mode               string   `json:"mode"`
	Product            string   `json:"product"`
	Description        string   `json:"description"`
	Sent               string   `json:"sent"`
	Steps              []string `json:"steps"`
	RequiresFileCanary bool     `json:"requires_file_canary"`
	SHA256             string   `json:"sha256"`
	Signed             bool     `json:"signed"`
	Publisher          string   `json:"publisher"`
	SignatureError     string   `json:"signature_error"`
	Installable        bool     `json:"installable"`
	Content            string   `json:"content"`
	Replaces           string   `json:"replaces,omitempty"`
}

func (s *Server) preview(ctx context.Context, data []byte, sig string) (pluginPreview, error) {
	c, err := s.Plugins.Inspect(ctx, data, sig)
	if err != nil {
		return pluginPreview{}, err
	}
	st, _ := settings.Load(ctx, s.DB)
	p := c.Plugin
	out := pluginPreview{ID: p.ID, Name: p.Name, Version: p.Version, CVEs: p.CVEs, Mode: p.Mode, Product: p.Product,
		Description: p.Description, Sent: p.Sent, RequiresFileCanary: p.RequiresFileCanary(), SHA256: c.SHA256,
		Signed: c.Signed, Publisher: c.Publisher, SignatureError: c.SigError, Installable: c.Signed || st.AllowUnsignedPlugins,
		Content: string(data)}
	for _, step := range p.Steps {
		if step.HTTP != nil {
			path := step.HTTP.Path
			if path == "" {
				path = "(URL cible)"
			}
			out.Steps = append(out.Steps, fmt.Sprintf("%s · HTTP %s %s", step.ID, step.HTTP.Method, path))
		} else {
			port := "port de l'asset"
			if step.TCP.Port > 0 {
				port = fmt.Sprint(step.TCP.Port)
			} else if p.DefaultPort > 0 {
				port = fmt.Sprint(p.DefaultPort)
			}
			out.Steps = append(out.Steps, fmt.Sprintf("%s · TCP %s%s", step.ID, port, map[bool]string{true: " (TLS)", false: ""}[step.TCP.TLS]))
		}
	}
	var cur string
	if err := s.DB.QueryRow(ctx, `SELECT version FROM plugins WHERE id = $1`, p.ID).Scan(&cur); err == nil {
		out.Replaces = cur
	}
	return out, nil
}

func (s *Server) previewPlugin(w http.ResponseWriter, r *http.Request, u *User) {
	var in pluginInput
	if !readJSON(w, r, &in) {
		return
	}
	data, sig, _, err := s.resolveInput(r.Context(), in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	pv, err := s.preview(r.Context(), data, sig)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pv)
}

func (s *Server) installPlugin(w http.ResponseWriter, r *http.Request, u *User) {
	var in pluginInput
	if !readJSON(w, r, &in) {
		return
	}
	ctx := r.Context()
	data, sig, source, err := s.resolveInput(ctx, in)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	st, err := settings.Load(ctx, s.DB)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Plugins.Install(ctx, data, sig, source, u.ID, st.AllowUnsignedPlugins)
	if err != nil {
		if c.Plugin != nil {
			s.audit(r, u, "Refus", fmt.Sprintf("plugin %s %s refusé : %v", c.Plugin.ID, c.Plugin.Version, err))
		}
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	detail := fmt.Sprintf("%s %s · signé par %s · sha256 %s · source %s", c.Plugin.ID, c.Plugin.Version, c.Publisher, c.SHA256[:12], source)
	if !c.Signed {
		detail = fmt.Sprintf("%s %s · NON SIGNÉ (mode développeur) · sha256 %s · source %s", c.Plugin.ID, c.Plugin.Version, c.SHA256[:12], source)
	}
	s.audit(r, u, "Plugin installé", detail)
	writeJSON(w, http.StatusCreated, map[string]any{"id": c.Plugin.ID, "signed": c.Signed})
}

func (s *Server) togglePlugin(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	st, _ := settings.Load(r.Context(), s.DB)
	if err := s.Plugins.SetEnabled(r.Context(), id, in.Enabled, st.AllowUnsignedPlugins); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Plugin modifié", fmt.Sprintf("%s %s", id, map[bool]string{true: "activé", false: "désactivé"}[in.Enabled]))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) deletePlugin(w http.ResponseWriter, r *http.Request, u *User) {
	id := r.PathValue("id")
	if err := s.Plugins.Remove(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Plugin désinstallé", id)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// registry renvoie l'index du dépôt de plugins configuré, avec l'état d'installation de chacun.
func (s *Server) pluginRegistry(w http.ResponseWriter, r *http.Request, u *User) {
	base := strings.TrimRight(s.Cfg.PluginRegistry, "/") + "/"
	b, err := fetchPublic(r.Context(), base+"index.json", 1<<20)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "dépôt de plugins injoignable ("+base+") : "+err.Error())
		return
	}
	var idx struct {
		Publisher string `json:"publisher"`
		PublicKey string `json:"public_key"`
		Plugins   []struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			Version     string   `json:"version"`
			CVEs        []string `json:"cves"`
			Mode        string   `json:"mode"`
			Product     string   `json:"product"`
			Description string   `json:"description"`
			File        string   `json:"file"`
		} `json:"plugins"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		writeErr(w, http.StatusBadGateway, "index.json illisible")
		return
	}
	type entry struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		Version     string   `json:"version"`
		CVEs        []string `json:"cves"`
		Mode        string   `json:"mode"`
		Product     string   `json:"product"`
		Description string   `json:"description"`
		URL         string   `json:"url"`
		Installed   string   `json:"installed"`
	}
	out := struct {
		Registry  string  `json:"registry"`
		Publisher string  `json:"publisher"`
		Plugins   []entry `json:"plugins"`
	}{Registry: base, Publisher: idx.Publisher, Plugins: []entry{}}
	for _, p := range idx.Plugins {
		if strings.Contains(p.File, "/") || strings.Contains(p.File, "..") {
			continue
		}
		e := entry{ID: p.ID, Name: p.Name, Version: p.Version, CVEs: p.CVEs, Mode: p.Mode, Product: p.Product, Description: p.Description, URL: base + p.File}
		_ = s.DB.QueryRow(r.Context(), `SELECT version FROM plugins WHERE id = $1`, p.ID).Scan(&e.Installed)
		out.Plugins = append(out.Plugins, e)
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------------------------
// Éditeurs de confiance

func (s *Server) listPublishers(w http.ResponseWriter, r *http.Request, u *User) {
	rows, err := s.DB.Query(r.Context(), `SELECT p.id, p.name, p.public_key, p.key_id, p.builtin, COALESCE(u.email, ''), p.created_at
		FROM publishers p LEFT JOIN users u ON u.id = p.added_by ORDER BY p.id`)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	type row struct {
		ID        int64     `json:"id"`
		Name      string    `json:"name"`
		PublicKey string    `json:"public_key"`
		KeyID     string    `json:"key_id"`
		Builtin   bool      `json:"builtin"`
		AddedBy   string    `json:"added_by"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := []row{}
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.ID, &x.Name, &x.PublicKey, &x.KeyID, &x.Builtin, &x.AddedBy, &x.CreatedAt); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) addPublisher(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	pub, err := plugin.ParsePublicKey(in.PublicKey)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.TrimSpace(in.Name)
	if len(name) < 2 || len(name) > 80 {
		writeErr(w, http.StatusBadRequest, "nom de l'éditeur obligatoire")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `INSERT INTO publishers (name, public_key, key_id, added_by) VALUES ($1, $2, $3, $4)`,
		name, strings.TrimSpace(in.PublicKey), plugin.KeyID(pub), u.ID); err != nil {
		writeErr(w, http.StatusConflict, "cette clé est déjà approuvée")
		return
	}
	s.audit(r, u, "Éditeur approuvé", fmt.Sprintf("%s · clé %s", name, plugin.KeyID(pub)))
	writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
}

func (s *Server) deletePublisher(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var name, keyID string
	err := s.DB.QueryRow(r.Context(), `DELETE FROM publishers WHERE id = $1 AND NOT builtin RETURNING name, key_id`, id).Scan(&name, &keyID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeErr(w, http.StatusBadRequest, "éditeur introuvable ou intégré (l'éditeur officiel ne se retire pas)")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Les plugins de cet éditeur ne se chargent plus.
	st, _ := settings.Load(r.Context(), s.DB)
	_ = s.Plugins.Load(r.Context(), st.AllowUnsignedPlugins)
	s.audit(r, u, "Éditeur retiré", fmt.Sprintf("%s · clé %s", name, keyID))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------------------------------------
// Canari fichier

type fileCanary struct {
	Path      string    `json:"path"`
	Token     string    `json:"token"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	Linux     string    `json:"linux"`
	Windows   string    `json:"windows"`
}

func canaryInstructions(c *fileCanary) {
	c.Content = c.Token + "\n"
	if strings.HasPrefix(c.Path, "/") {
		dir := c.Path[:strings.LastIndex(c.Path, "/")]
		if dir == "" {
			dir = "/"
		}
		c.Linux = fmt.Sprintf("sudo mkdir -p %s && printf '%%s\\n' '%s' | sudo tee %s >/dev/null && sudo chmod 644 %s", shellQuote(dir), c.Token, shellQuote(c.Path), shellQuote(c.Path))
	} else {
		c.Windows = fmt.Sprintf("New-Item -ItemType Directory -Force -Path (Split-Path '%s') | Out-Null; Set-Content -Path '%s' -Value '%s' -Encoding ascii", c.Path, c.Path, c.Token)
	}
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (s *Server) getFileCanary(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var c fileCanary
	err := s.DB.QueryRow(r.Context(), `SELECT path, token, created_at FROM asset_canaries WHERE asset_id = $1`, id).Scan(&c.Path, &c.Token, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, nil)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	canaryInstructions(&c)
	writeJSON(w, http.StatusOK, c)
}

func validCanaryPath(p string) bool {
	if len(p) < 3 || len(p) > 200 || strings.ContainsAny(p, "\r\n\x00'\"`$;&|<>?*%#") {
		return false
	}
	if strings.HasPrefix(p, "/") {
		return !strings.HasSuffix(p, "/") && !strings.Contains(p, "/../")
	}
	// Chemin Windows absolu : C:\dossier\fichier.txt
	return len(p) > 3 && p[1] == ':' && p[2] == '\\' && (p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z')
}

func (s *Server) setFileCanary(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	var in struct {
		Path string `json:"path"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	path := strings.TrimSpace(in.Path)
	if !validCanaryPath(path) {
		writeErr(w, http.StatusBadRequest, "chemin absolu attendu (ex. /opt/opencvec/canary.txt ou C:\\ProgramData\\OpenCVEC\\canary.txt), sans espace ni caractère spécial")
		return
	}
	var host string
	if err := s.DB.QueryRow(r.Context(), `SELECT host FROM assets WHERE id = $1`, id).Scan(&host); err != nil {
		s.fail(w, r, err)
		return
	}
	tok := s.Corr.Signer.New(id, 0)
	if _, err := s.DB.Exec(r.Context(), `INSERT INTO asset_canaries (asset_id, token, path) VALUES ($1, $2, $3)
		ON CONFLICT (asset_id) DO UPDATE SET token = EXCLUDED.token, path = EXCLUDED.path, created_at = now()`, id, tok, path); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Canari fichier", fmt.Sprintf("%s · nouveau jeton à déposer dans %s", host, path))
	c := fileCanary{Path: path, Token: tok, CreatedAt: time.Now()}
	canaryInstructions(&c)
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) deleteFileCanary(w http.ResponseWriter, r *http.Request, u *User) {
	id, ok := pathID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "identifiant invalide")
		return
	}
	if _, err := s.DB.Exec(r.Context(), `DELETE FROM asset_canaries WHERE asset_id = $1`, id); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, u, "Canari fichier", fmt.Sprintf("asset #%d · canari retiré", id))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
