# XDR/MDM — geliştirme görevleri
# Not: Go, buf ve protoc-gen eklentileri kurulu olmalı (bkz. README).

.PHONY: proto tidy build build-server build-agent build-watchdog test e2e dev-certs clean

## proto: .proto dosyalarından Go kodunu üretir (gen/ altına).
proto:
	buf lint
	buf generate

## tidy: go.mod/go.sum düzenler.
tidy:
	go mod tidy

## build: tüm ikilileri derler.
build: build-server build-agent build-watchdog

build-server:
	go build -o bin/c2 ./server/cmd/c2

build-agent:
	go build -o bin/agent ./agent/cmd/agent

build-watchdog:
	go build -o bin/watchdog ./agent/cmd/watchdog

## test: tüm birim + entegrasyon testlerini çalıştırır.
test:
	go test ./...

## e2e: yalnız uçtan-uca entegrasyon testini çalıştırır (gerçek mTLS gRPC).
e2e:
	go test -v ./server/internal/e2e/...

## dev-certs: GELİŞTİRME CA + sunucu sertifikası üretir (./dev-certs).
dev-certs:
	go run ./tools/gencerts -out ./dev-certs -name xdr-c2

clean:
	rm -rf bin gen dist dev-certs
