package patatt

import (
	"fmt"
	"os"
)

type LogLevel int

const (
	INFO LogLevel = iota
	DEBUG
	CRITICAL
)

var level LogLevel = CRITICAL

func SetLogLevel(ll LogLevel) {
	level = ll
}

func Infof(format string, a ...any) {
	if level <= INFO {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

func Debugf(format string, a ...any) {
	if level <= DEBUG {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}

func Criticalf(format string, a ...any) {
	if level <= CRITICAL {
		fmt.Fprintf(os.Stderr, format, a...)
	}
}
