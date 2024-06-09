package patatt

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	crlf = "\r\n"
	lf   = "\n"
)

// canonicalize removes multiple WSP and adds a CRLF line ending
func canonicalize(hval string) string {

	// replace multiple WSP with a single SP
	hval = strings.Join(strings.Fields(hval), " ")

	// trim all WSP at end
	return strings.TrimSpace(hval) + crlf
}

// n normalizes a string to lower case and trims whitespace
func n(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// delWSP removes any WSP within the string
func delWSP(s string) string { return strings.Join(strings.Fields(s), "") }

// NewCRLFReader returns a reader with CRLF line endings
func NewCRLFReader(r io.Reader) io.Reader {
	var buf bytes.Buffer
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		buf.WriteString(scanner.Text() + crlf)
	}
	return &buf
}

func exists(fn string) bool {
	_, err := os.Stat(fn)
	return os.IsExist(err)
}

func getDataDir() string {
	dir := os.Getenv("XDG_DATA_HOME")
	if dir != "" {
		return dir
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	return filepath.Join(home, ".local", "share", "patatt")
}
