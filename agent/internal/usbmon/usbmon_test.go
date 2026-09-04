package usbmon

import "testing"

func TestParseWinDrives(t *testing.T) {
	out := "\r\ndrive=E:|KINGSTON\r\ndrive=F:|\r\nignored line\r\n"
	ds := parseWinDrives(out)
	if len(ds) != 2 {
		t.Fatalf("2 sürücü beklenirdi, %d: %+v", len(ds), ds)
	}
	if ds[0].ID != "E:" || ds[0].Label != "KINGSTON" {
		t.Fatalf("sürücü[0] hatalı: %+v", ds[0])
	}
	if ds[1].ID != "F:" || ds[1].Label != "" {
		t.Fatalf("sürücü[1] (etiketsiz) hatalı: %+v", ds[1])
	}
}

func TestDriveKey(t *testing.T) {
	if (Drive{ID: "E:"}).Key() != "E:" {
		t.Fatal("Key ID döndürmeli")
	}
}

func TestNewScannerNonNil(t *testing.T) {
	if NewScanner() == nil {
		t.Fatal("NewScanner nil dönmemeli")
	}
}
