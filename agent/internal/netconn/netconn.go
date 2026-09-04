// Package netconn, uç noktanın kurulu (established) giden ağ bağlantılarını
// toplar (süreç-başına C2/dışa-sızma görünürlüğü). Uzak IP'ler sunucu-taraflı
// IoC motoruyla eşleştirilir. OS-özel sorgular exec/proc ile yapılır; ayrıştırma
// platform-bağımsız ve test edilebilir tutulur (discovery/inventory ile aynı desen).
package netconn

import (
	"strconv"
	"strings"
)

// Conn, kurulu bir giden TCP bağlantısıdır.
type Conn struct {
	RemoteIP   string
	RemotePort int
	LocalPort  int
	PID        int // 0 = bilinmiyor (Linux /proc/net/tcp'de süreç eşlemesi yok)
}

// Key, bağlantının tekilleştirme anahtarıdır (yeni-bağlantı takibi için).
func (c Conn) Key() string {
	return c.RemoteIP + ":" + strconv.Itoa(c.RemotePort) + "/" + strconv.Itoa(c.PID)
}

// Scanner, OS-özel bağlantı numaralandırması sağlar.
type Scanner interface {
	// Scan, kurulu giden bağlantıları döner (loopback/dinleme hariç). Alınamazsa boş.
	Scan() []Conn
}

// Scan, mevcut platformun bağlantı listesini döner.
func Scan() []Conn { return NewScanner().Scan() }

// isLoopbackOrEmpty, bir uzak IP'nin loopback/boş/bağlanmamış olup olmadığını söyler
// (bunlar giden bağlantı olarak raporlanmaz).
func isLoopbackOrEmpty(ip string) bool {
	if ip == "" || ip == "0.0.0.0" || ip == "*" || ip == "::" {
		return true
	}
	return strings.HasPrefix(ip, "127.") || ip == "::1"
}

// parseNetstat, Windows `netstat -ano -p TCP` çıktısından KURULU giden
// bağlantıları çıkarır. Satır biçimi:
//
//	TCP    192.168.0.5:52341      93.184.216.34:443      ESTABLISHED     1234
//
// Loopback/dinleme atlanır. IPv6 köşeli-parantez adresleri de ayrıştırılır.
func parseNetstat(out string) []Conn {
	var conns []Conn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || !strings.EqualFold(f[0], "TCP") {
			continue
		}
		if !strings.EqualFold(f[3], "ESTABLISHED") {
			continue
		}
		_, lport := splitHostPort(f[1])
		rip, rport := splitHostPort(f[2])
		if isLoopbackOrEmpty(rip) {
			continue
		}
		pid, _ := strconv.Atoi(f[4])
		conns = append(conns, Conn{RemoteIP: rip, RemotePort: rport, LocalPort: lport, PID: pid})
	}
	return conns
}

// splitHostPort, "ip:port" veya "[ipv6]:port" değerini ayırır. Ayrıştırılamazsa
// port 0 döner.
func splitHostPort(s string) (host string, port int) {
	// IPv6 köşeli parantez: [::1]:443
	if strings.HasPrefix(s, "[") {
		if i := strings.LastIndex(s, "]:"); i >= 0 {
			host = s[1:i]
			port, _ = strconv.Atoi(s[i+2:])
			return host, port
		}
	}
	if i := strings.LastIndexByte(s, ':'); i >= 0 {
		host = s[:i]
		port, _ = strconv.Atoi(s[i+1:])
		return host, port
	}
	return s, 0
}

// parseProcNetTcp, Linux /proc/net/tcp (veya tcp6) içeriğinden KURULU (st=01)
// giden bağlantıları çıkarır. Adresler küçük-endian hex "IP:PORT" biçimindedir;
// /proc/net/tcp'de süreç eşlemesi olmadığından PID=0. IPv4 (8 hex) ayrıştırılır.
func parseProcNetTcp(out string) []Conn {
	var conns []Conn
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "sl" { // başlık
			continue
		}
		if f[3] != "01" { // 01 = ESTABLISHED
			continue
		}
		_, lport := parseHexAddr(f[1])
		rip, rport := parseHexAddr(f[2])
		if rip == "" || isLoopbackOrEmpty(rip) {
			continue
		}
		conns = append(conns, Conn{RemoteIP: rip, RemotePort: rport, LocalPort: lport})
	}
	return conns
}

// parseHexAddr, /proc/net/tcp "AABBCCDD:PPPP" (küçük-endian IPv4 hex + port hex)
// değerini "a.b.c.d", port olarak döner. Yalnız 8-haneli (IPv4) ele alınır.
func parseHexAddr(s string) (ip string, port int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || len(parts[0]) != 8 {
		return "", 0
	}
	b := make([]int64, 4)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseInt(parts[0][i*2:i*2+2], 16, 0)
		if err != nil {
			return "", 0
		}
		b[3-i] = v // küçük-endian → tersle
	}
	p, err := strconv.ParseInt(parts[1], 16, 0)
	if err != nil {
		return "", 0
	}
	return strconv.FormatInt(b[0], 10) + "." + strconv.FormatInt(b[1], 10) + "." +
		strconv.FormatInt(b[2], 10) + "." + strconv.FormatInt(b[3], 10), int(p)
}
