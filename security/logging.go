package security

import (
	"log"
	"os"
	"time"
)

// Logger is a simple logging structure
type Logger struct {
	file *os.File
}

// NewLogger creates a new logger instance
func NewLogger(filePath string) (*Logger, error) {
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		return nil, err
	}
	return &Logger{file: file}, nil
}

// LogLoginActivity logs login activities with timestamp and user information
func (l *Logger) LogLoginActivity(username string, success bool) {
	status := "FAILED"
	if success {
		status = "SUCCESS"
	}
	log.SetOutput(l.file)
	log.Printf("%s - Login attempt by user: %s, Status: %s\n", time.Now().Format(time.RFC3339), username, status)
}

// Close closes the logger file
func (l *Logger) Close() error {
	return l.file.Close()
}
