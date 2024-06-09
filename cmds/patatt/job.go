package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
)

const stdin = "-"

type Job struct {
	data []byte
	fn   string
}

func NewJob(fn string) (job Job, err error) {
	job.fn = fn
	if fn == stdin {
		job.data, err = io.ReadAll(os.Stdin)
		if err != nil {
			return
		}
	} else {
		job.data, err = os.ReadFile(fn)
		if err != nil {
			return
		}
	}
	return
}

func (s Job) Reader() io.Reader {
	return bytes.NewReader(s.data)
}

func (s Job) UseStdin() bool {
	return s.fn == stdin
}

func (s Job) FileName() string {
	return s.fn
}

func (s Job) Base() string {
	if s.UseStdin() {
		return s.fn
	}
	return filepath.Base(s.fn)
}

func (s Job) JobName() string {
	d := s.data
	i := bytes.IndexAny(d, "\r\n")
	if i < 0 {
		return ""
	}
	re := regexp.MustCompile("^From ([a-zA-Z0-9]+) ")
	matches := re.FindStringSubmatch(string(d[:i]))
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

func Process(args []string, do func(Job) error) error {
	if len(args) == 0 {
		args = append(args, stdin)
	}

	for _, fn := range args {
		j, err := NewJob(fn)
		if err != nil {
			return err
		}
		err = do(j)
		if err != nil {
			return err
		}
	}
	return nil
}
