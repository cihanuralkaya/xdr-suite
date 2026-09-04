package netconn

import "testing"

func TestParseNetstat(t *testing.T) {
	out := "\r\nActive Connections\r\n" +
		"  Proto  Local Address          Foreign Address        State           PID\r\n" +
		"  TCP    192.168.0.5:52341      93.184.216.34:443      ESTABLISHED     1234\r\n" +
		"  TCP    127.0.0.1:8445         127.0.0.1:60546        ESTABLISHED     42\r\n" + // loopback → atla
		"  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\r\n" + // dinleme → atla
		"  TCP    10.0.0.2:50000         10.0.0.9:22            ESTABLISHED     777\r\n"
	conns := parseNetstat(out)
	if len(conns) != 2 {
		t.Fatalf("2 kurulu giden bağlantı beklenirdi, %d: %+v", len(conns), conns)
	}
	if conns[0].RemoteIP != "93.184.216.34" || conns[0].RemotePort != 443 || conns[0].PID != 1234 {
		t.Fatalf("bağlantı[0] hatalı: %+v", conns[0])
	}
	if conns[1].RemoteIP != "10.0.0.9" || conns[1].RemotePort != 22 || conns[1].PID != 777 {
		t.Fatalf("bağlantı[1] hatalı: %+v", conns[1])
	}
}

func TestSplitHostPort(t *testing.T) {
	h, p := splitHostPort("1.2.3.4:443")
	if h != "1.2.3.4" || p != 443 {
		t.Fatalf("ipv4 hatalı: %s:%d", h, p)
	}
	h, p = splitHostPort("[fe80::1]:22")
	if h != "fe80::1" || p != 22 {
		t.Fatalf("ipv6 hatalı: %s:%d", h, p)
	}
}

func TestParseProcNetTcp(t *testing.T) {
	// rem_address 2216A8C0:01BB = 192.168.22.34:443 (küçük-endian), st=01 (ESTABLISHED)
	// ikinci satır st=0A (LISTEN) → atla; üçüncü loopback (0100007F) → atla.
	out := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0500A8C0:CC65 2216A8C0:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 12345\n" +
		"   1: 00000000:01BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22\n" +
		"   2: 0100007F:8A9D 0100007F:ECB2 01 00000000:00000000 00:00000000 00000000  1000        0 33\n"
	conns := parseProcNetTcp(out)
	if len(conns) != 1 {
		t.Fatalf("1 kurulu bağlantı beklenirdi, %d: %+v", len(conns), conns)
	}
	if conns[0].RemoteIP != "192.168.22.34" || conns[0].RemotePort != 443 {
		t.Fatalf("proc bağlantı hatalı: %+v", conns[0])
	}
}

func TestIsLoopbackOrEmpty(t *testing.T) {
	for _, ip := range []string{"", "0.0.0.0", "127.0.0.1", "127.5.5.5", "::1", "::"} {
		if !isLoopbackOrEmpty(ip) {
			t.Errorf("%q loopback/boş sayılmalıydı", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "192.168.1.1", "10.0.0.9"} {
		if isLoopbackOrEmpty(ip) {
			t.Errorf("%q raporlanabilir olmalıydı", ip)
		}
	}
}

func TestConnKeyDedup(t *testing.T) {
	a := Conn{RemoteIP: "1.2.3.4", RemotePort: 443, PID: 10}
	b := Conn{RemoteIP: "1.2.3.4", RemotePort: 443, PID: 10}
	c := Conn{RemoteIP: "1.2.3.4", RemotePort: 80, PID: 10}
	if a.Key() != b.Key() {
		t.Fatal("aynı bağlantı aynı anahtar üretmeli")
	}
	if a.Key() == c.Key() {
		t.Fatal("farklı port farklı anahtar üretmeli")
	}
}

func TestNewScannerNonNil(t *testing.T) {
	if NewScanner() == nil {
		t.Fatal("NewScanner nil dönmemeli")
	}
}
