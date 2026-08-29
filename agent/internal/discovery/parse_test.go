package discovery

import "testing"

func TestParseWindowsARP(t *testing.T) {
	sample := `
Interface: 192.168.1.10 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.20          00-11-22-33-44-55     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
`
	hosts := ParseWindowsARP(sample)
	if len(hosts) != 2 {
		t.Fatalf("2 gerçek host beklenirdi (yayın/multicast atlanmalı), %d: %+v", len(hosts), hosts)
	}
	if hosts[0].IP != "192.168.1.1" || hosts[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("ilk host yanlış: %+v", hosts[0])
	}
}

func TestParseProcNetARP(t *testing.T) {
	sample := `IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.1.50     0x1         0x2         00:11:22:33:44:66     *        eth0
`
	hosts := ParseProcNetARP(sample)
	if len(hosts) != 2 {
		t.Fatalf("2 host beklenirdi, %d", len(hosts))
	}
	if hosts[1].IP != "192.168.1.50" || hosts[1].MAC != "00:11:22:33:44:66" {
		t.Errorf("ikinci host yanlış: %+v", hosts[1])
	}
}

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA-BB-CC-DD-EE-FF": "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":    "aa:bb:cc:dd:ee:ff",
	}
	for in, want := range cases {
		if got := NormalizeMAC(in); got != want {
			t.Errorf("NormalizeMAC(%q)=%q, beklenen %q", in, got, want)
		}
	}
}

func TestBroadcastFiltered(t *testing.T) {
	if !isBroadcastOrMulticast("ff:ff:ff:ff:ff:ff") {
		t.Error("yayın adresi filtrelenmeliydi")
	}
	if !isBroadcastOrMulticast("01:00:5e:00:00:16") {
		t.Error("multicast (ilk bayt tek) filtrelenmeliydi")
	}
	if isBroadcastOrMulticast("aa:bb:cc:dd:ee:ff") {
		t.Error("normal unicast filtrelenmemeliydi")
	}
}
