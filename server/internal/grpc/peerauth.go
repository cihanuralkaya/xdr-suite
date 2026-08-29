package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ErrNoPeerIdentity, çağrıda doğrulanmış bir istemci sertifikası bulunmadığında döner.
var ErrNoPeerIdentity = errors.New("grpc: mTLS istemci kimliği yok")

// DeviceIDFromContext, kimliği mTLS istemci sertifikasının CN'inden (=device_id)
// çıkarır. Bu, güvenliğin kritik noktasıdır: sunucu, isteğin GÖVDESİNDE gelen
// device_id'ye asla güvenmez; kimliği daima kriptografik olarak doğrulanmış
// sertifikadan alır (inceleme güven sınırı).
func DeviceIDFromContext(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", ErrNoPeerIdentity
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", ErrNoPeerIdentity
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 || certs[0].Subject.CommonName == "" {
		return "", ErrNoPeerIdentity
	}
	return certs[0].Subject.CommonName, nil
}
