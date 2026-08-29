//go:build !windows

package discovery

import "os"

// NewNeighborSource, Linux/diğer platformlarda komşu kaynağı döner.
// Linux'ta /proc/net/arp okunur (read-only); dosya yoksa boş sonuç döner.
func NewNeighborSource() NeighborSource { return procArpSource{} }

type procArpSource struct{}

func (procArpSource) Neighbors() ([]Host, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		// Dosya yoksa (ör. macOS) sessizce boş dön; keşif devre dışı kalır.
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return ParseProcNetARP(string(data)), nil
}
