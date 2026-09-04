package compliance

import "testing"

func TestParseBitLockerStatus(t *testing.T) {
	on := "Volume C: [OS]\n  Conversion Status: Fully Encrypted\n  Protection Status: Protection On\n"
	off := "Volume C:\n  Protection Status: Protection Off\n"
	cases := []struct{ in, want string }{
		{on, EncOn},
		{off, EncOff},
		{"koruma açık", EncOn},
		{"koruma kapalı", EncOff},
		{"belirsiz çıktı", EncUnknown},
		{"", EncUnknown},
	}
	for _, c := range cases {
		if got := parseBitLockerStatus(c.in); got != c.want {
			t.Errorf("parseBitLockerStatus(%q)=%s beklenen %s", c.in, got, c.want)
		}
	}
}

func TestParseLsblkCrypt(t *testing.T) {
	cases := []struct{ in, want string }{
		{"disk\npart\ncrypt\nlvm\n", EncOn},
		{"disk\npart\nlvm\n", EncOff},
		{"CRYPT\n", EncOn}, // büyük harf
		{"", EncUnknown},
		{"   ", EncUnknown},
	}
	for _, c := range cases {
		if got := parseLsblkCrypt(c.in); got != c.want {
			t.Errorf("parseLsblkCrypt(%q)=%s beklenen %s", c.in, got, c.want)
		}
	}
}

func TestParseNetshFirewall(t *testing.T) {
	allOn := "Domain Profile Settings:\n----\nState                                 ON\n\nPrivate Profile Settings:\n----\nState                                 ON\n\nPublic Profile Settings:\n----\nState                                 ON\n"
	oneOff := "Domain Profile Settings:\nState                                 ON\nPrivate Profile Settings:\nState                                 OFF\n"
	cases := []struct{ in, want string }{
		{allOn, FwOn},
		{oneOff, FwOff}, // herhangi bir profil kapalı → off
		{"Durum                                 AÇIK\n", FwOn},
		{"Durum                                 KAPALI\n", FwOff},
		{"no state lines here", FwUnknown},
		{"", FwUnknown},
	}
	for _, c := range cases {
		if got := parseNetshFirewall(c.in); got != c.want {
			t.Errorf("parseNetshFirewall(%q)=%s beklenen %s", c.in, got, c.want)
		}
	}
}

func TestParseUfwStatus(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Status: active\n", FwOn},
		{"Status: inactive\n", FwOff},
		{"command not found", FwUnknown},
		{"", FwUnknown},
	}
	for _, c := range cases {
		if got := parseUfwStatus(c.in); got != c.want {
			t.Errorf("parseUfwStatus(%q)=%s beklenen %s", c.in, got, c.want)
		}
	}
}

func TestNewCheckerReturnsNonNil(t *testing.T) {
	if NewChecker() == nil {
		t.Fatal("NewChecker nil dönmemeli")
	}
}
