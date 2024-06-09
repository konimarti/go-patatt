package patatt

import (
	"bytes"
	"io"
	"os/exec"
)

func CommandIO(cmd *exec.Cmd, in io.Reader) (stdout *bytes.Buffer, stderr *bytes.Buffer) {
	stdout = new(bytes.Buffer)
	stderr = new(bytes.Buffer)

	cmd.Stdin = in
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	return stdout, stderr
}

func ExitCode(cmd *exec.Cmd) int {
	if cmd != nil && cmd.ProcessState != nil {
		return cmd.ProcessState.ExitCode()
	}
	return 0
}

func DefaultGPGArgs() []string {
	return []string{"--batch", "--no-auto-key-retrieve", "--no-auto-check-trustdb"}
}
