//go:build !windows && !linux

package enforce

import "errors"

// ErrUnsupported, süreç kontrolünün bu platformda desteklenmediğini belirtir
// (ör. macOS). Windows ve Linux'ta gerçek implementasyonlar vardır.
var ErrUnsupported = errors.New("enforce: bu platformda süreç kontrolü desteklenmiyor")

type noopController struct{}

// NewProcessController, mevcut platform için süreç kontrolcüsü döner.
func NewProcessController() ProcessController { return noopController{} }

func (noopController) List() ([]Process, error) { return nil, ErrUnsupported }
func (noopController) Kill(uint32) error        { return ErrUnsupported }
