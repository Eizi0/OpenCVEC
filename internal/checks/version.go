package checks

import (
	"strconv"
	"strings"
)

// version est une version numérique x.y.z (les suffixes sont ignorés).
type version [3]int

func parseVersion(s string) (version, bool) {
	var v version
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ".", 4)
	if len(parts) < 2 {
		return v, false
	}
	for i := 0; i < 3 && i < len(parts); i++ {
		p := parts[i]
		end := 0
		for end < len(p) && p[end] >= '0' && p[end] <= '9' {
			end++
		}
		if end == 0 {
			return v, false
		}
		n, err := strconv.Atoi(p[:end])
		if err != nil {
			return v, false
		}
		v[i] = n
		if end < len(p) {
			break
		}
	}
	return v, true
}

func (v version) less(o version) bool {
	for i := 0; i < 3; i++ {
		if v[i] != o[i] {
			return v[i] < o[i]
		}
	}
	return false
}

func (v version) branch() [2]int { return [2]int{v[0], v[1]} }

func (v version) String() string {
	return strconv.Itoa(v[0]) + "." + strconv.Itoa(v[1]) + "." + strconv.Itoa(v[2])
}
