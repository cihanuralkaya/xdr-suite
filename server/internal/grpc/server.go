package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	xdrv1 "xdr.corp/suite/gen/xdr/v1"
	"xdr.corp/suite/server/internal/revocation"
)

// TLSMaterial, sunucunun TLS/mTLS için ihtiyaç duyduğu PEM verileridir.
type TLSMaterial struct {
	ServerCertPEM []byte // gRPC sunucu sertifikası
	ServerKeyPEM  []byte // sunucu özel anahtarı
	ClientCAPEM   []byte // istemci (ajan) sertifikalarını doğrulayan CA
	// Revocation, verilirse iptal edilmiş istemci sertifikaları el sıkışmada
	// reddedilir (opsiyonel).
	Revocation *revocation.Cache
}

// buildTLS, sunucu TLS yapılandırması üretir. clientAuth istemci sertifikası
// politikasını belirler; NoClientCert dışındaki her modda ClientCA yüklenir.
func buildTLS(m TLSMaterial, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(m.ServerCertPEM, m.ServerKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("grpc: sunucu sertifika/anahtar yüklenemedi: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   clientAuth,
	}
	if clientAuth != tls.NoClientCert {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(m.ClientCAPEM) {
			return nil, errors.New("grpc: istemci CA PEM'i yüklenemedi")
		}
		cfg.ClientCAs = pool
		if m.Revocation != nil {
			cfg.VerifyPeerCertificate = revocation.VerifyPeerCertificate(m.Revocation)
		}
	}
	return cfg, nil
}

// NewAgentServer, mTLS'li AgentService gRPC sunucusu oluşturur (istemci
// sertifikası ZORUNLU ve doğrulanır).
func NewAgentServer(m TLSMaterial, h *AgentHandler) (*grpc.Server, error) {
	tc, err := buildTLS(m, tls.RequireAndVerifyClientCert)
	if err != nil {
		return nil, err
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tc)))
	xdrv1.RegisterAgentServiceServer(s, h)
	return s, nil
}

// NewEnrollServer, EnrollmentService gRPC sunucusu oluşturur. İstemci
// sertifikası VARSA doğrulanır (VerifyClientCertIfGiven): yeni ajan sertifikasız
// Enroll eder; kayıtlı ajan RenewCertificate için mevcut sertifikasını sunar ve
// kimliği ondan alınır.
func NewEnrollServer(m TLSMaterial, h *EnrollmentHandler) (*grpc.Server, error) {
	tc, err := buildTLS(m, tls.VerifyClientCertIfGiven)
	if err != nil {
		return nil, err
	}
	s := grpc.NewServer(grpc.Creds(credentials.NewTLS(tc)))
	xdrv1.RegisterEnrollmentServiceServer(s, h)
	return s, nil
}

// Serve, sunucuyu verilen adreste dinletir (bloklar).
func Serve(s *grpc.Server, addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc: dinleme başarısız (%s): %w", addr, err)
	}
	return s.Serve(lis)
}
