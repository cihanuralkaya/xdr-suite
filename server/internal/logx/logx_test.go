package logx

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestJSONFormatDetection(t *testing.T) {
	if !jsonFormat("json") || !jsonFormat("JSON") || !jsonFormat(" json ") {
		t.Fatal("json biçimi tanınmalıydı")
	}
	if jsonFormat("text") || jsonFormat("") {
		t.Fatal("text/boş json sayılmamalıydı")
	}
}

func TestJSONLoggerEmitsStructured(t *testing.T) {
	var buf bytes.Buffer
	l := newJSONLogger(&buf)
	l.Info("ajan başladı", "device", "d-1")

	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("çıktı geçerli JSON olmalıydı: %v (%q)", err, buf.String())
	}
	if m["msg"] != "ajan başladı" || m["device"] != "d-1" || m["level"] != "INFO" {
		t.Fatalf("beklenen alanlar yok: %+v", m)
	}
}

func TestSlogWriterWrapsStdLog(t *testing.T) {
	var buf bytes.Buffer
	w := slogWriter{l: newJSONLogger(&buf)}
	_, _ = w.Write([]byte("[c2] dinleniyor :8445\n"))

	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &m); err != nil {
		t.Fatalf("std log satırı JSON'a sarılmalıydı: %v", err)
	}
	if m["msg"] != "[c2] dinleniyor :8445" {
		t.Fatalf("mesaj korunmalıydı (newline kırpılmış): %+v", m)
	}
}
