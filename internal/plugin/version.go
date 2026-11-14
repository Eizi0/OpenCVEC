package plugin

import (
	"fmt"
	"strconv"
	"strings"
)

// version est une version numérique (jusqu'à 4 composantes).
type version [4]int

func parseVersion(s string) (version, bool) {
	var v version
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) == 0 || len(parts) > 4 {
		return v, false
	}
	for i, p := range parts {
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		if end == 0 {
			return v, false
		}
		n, _ := strconv.Atoi(p[:end])
		v[i] = n
	}
	return v, true
}

func cmp(a, b version) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

type bound struct {
	op string
	v  version
}

type vrange []bound

// parseRange lit « >=8.5.1, <9.8.1 » (conditions combinées par ET).
func parseRange(s string) (vrange, error) {
	var out vrange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		op := ""
		for _, o := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(part, o) {
				op = o
				break
			}
		}
		if op == "" {
			return nil, fmt.Errorf("plage %q : opérateur attendu (>=, <=, >, <, =)", s)
		}
		v, ok := parseVersion(strings.TrimSpace(part[len(op):]))
		if !ok {
			return nil, fmt.Errorf("plage %q : version invalide", s)
		}
		out = append(out, bound{op, v})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("plage vide")
	}
	return out, nil
}

func (r vrange) contains(v version) bool {
	for _, b := range r {
		c := cmp(v, b.v)
		ok := map[string]bool{">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "=": c == 0}[b.op]
		if !ok {
			return false
		}
	}
	return true
}
