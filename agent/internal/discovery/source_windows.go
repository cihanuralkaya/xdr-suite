//go:build windows

package discovery

import "os/exec"

// NewNeighborSource, Windows komşu kaynağı döner (`arp -a`, read-only).
func NewNeighborSource() NeighborSource { return winArpSource{} }

type winArpSource struct{}

func (winArpSource) Neighbors() ([]Host, error) {
	out, err := exec.Command("arp", "-a").Output()
	if err != nil {
		return nil, err
	}
	return ParseWindowsARP(string(out)), nil
}
