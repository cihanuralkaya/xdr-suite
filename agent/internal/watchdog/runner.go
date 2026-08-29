package watchdog

import (
	"context"
	"os"
	"os/exec"
)

// ExecRunner, ajan ikilisini bir alt süreç olarak çalıştıran gerçek Runner'dır.
// Run, süreç çıkana dek bloklar; ctx iptal edilirse süreci sonlandırır.
type ExecRunner struct {
	path string
	args []string
}

// NewExecRunner oluşturur.
func NewExecRunner(path string, args ...string) *ExecRunner {
	return &ExecRunner{path: path, args: args}
}

// Run, ikiliyi başlatır ve çıkışını bekler.
func (r *ExecRunner) Run(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, r.path, r.args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = nil
	return cmd.Run()
}
