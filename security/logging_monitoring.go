package security

import (
    "log"
    "os"
    "time"
)

// Logger is a struct that holds the logger instance
type Logger struct {
    logger *log.Logger
}

// NewLogger initializes and returns a new Logger instance
func NewLogger(logFilePath string) (*Logger, error) {
    file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
    if err != nil {
        return nil, err
    }
    logger := log.New(file, "LOGIN: ", log.Ldate|log.Ltime|log.Lshortfile)
    return &Logger{logger: logger}, nil
}

// LogLoginAttempt logs a login attempt with the provided details
func (l *Logger) LogLoginAttempt(username string, success bool) {
    status := "FAILED"
    if success {
        status = "SUCCESS"
    }
    l.logger.Printf("User: %s, Status: %s, Timestamp: %s\n", username, status, time.Now().Format(time.RFC3339))
}

// MonitorLogs is a placeholder for future log monitoring implementation
func MonitorLogs() {
    // This function will be implemented to monitor logs for suspicious activities
}
