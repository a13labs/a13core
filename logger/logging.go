package logger

import (
	"os"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

type Level uint32

// A constant exposing all logging levels
var AllLevels = []Level{
	PanicLevel,
	FatalLevel,
	ErrorLevel,
	WarnLevel,
	InfoLevel,
	DebugLevel,
	TraceLevel,
}

const (
	PanicLevel Level = iota
	FatalLevel       = Level(logrus.FatalLevel)
	ErrorLevel       = Level(logrus.ErrorLevel)
	WarnLevel        = Level(logrus.WarnLevel)
	InfoLevel        = Level(logrus.InfoLevel)
	DebugLevel       = Level(logrus.DebugLevel)
	TraceLevel       = Level(logrus.TraceLevel)
)

func Init(logFile string) {
	log.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.SetOutput(file)
	} else {
		log.Warn("Failed to log to file, using default stderr")
	}
}

func Info(args ...interface{}) {
	log.Info(args...)
}

func Infof(format string, args ...interface{}) {
	log.Infof(format, args...)
}

func Warn(args ...interface{}) {
	log.Warn(args...)
}

func Warnf(format string, args ...interface{}) {
	log.Warnf(format, args...)
}

func Error(args ...interface{}) {
	log.Error(args...)
}

func Errorf(format string, args ...interface{}) {
	log.Errorf(format, args...)
}

func Debug(args ...interface{}) {
	log.Debug(args...)
}

func Debugf(format string, args ...interface{}) {
	log.Debugf(format, args...)
}

func Fatal(args ...interface{}) {
	log.Fatal(args...)
}

func Fatalf(format string, args ...interface{}) {
	log.Fatalf(format, args...)
}

func ParseLevel(level string) (Level, error) {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		return 0, err
	}
	return Level(l), nil
}

func SetLevel(level Level) {
	log.SetLevel(logrus.Level(level))
}
