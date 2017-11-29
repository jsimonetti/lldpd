package lldpd

import (
	"github.com/sirupsen/logrus"
)

// Logger is a logging adapter interface
type Logger interface {
	// Info logs informational messages.
	Info(keyvals ...interface{})
	// Error logs error messages.
	Error(keyvals ...interface{})
}

// adapter is a thin wrapper around the logrus logger that adapts it to
// the Logger interface.
type adapter struct {
	logrus *logrus.Entry
}

// Adapt creates a Logger backed from a logrus Entry.
func Adapt(l *logrus.Entry) Logger {
	return &adapter{l}
}

func (a *adapter) Info(keyvals ...interface{}) {
	fields := a.fields(keyvals...)
	a.logrus.WithFields(fields).Info()
}
func (a *adapter) Error(keyvals ...interface{}) {
	fields := a.fields(keyvals...)
	a.logrus.WithFields(fields).Info()
}

func (a *adapter) fields(keyvals ...interface{}) logrus.Fields {
	if len(keyvals)%2 != 0 {
		keyvals = append(keyvals, "MISSING")
	}

	fields := make(logrus.Fields)

	for i := 0; i < len(keyvals); i += 2 {
		k := keyvals[i].(string)
		v := keyvals[i+1]
		fields[k] = v
	}

	return fields
}
