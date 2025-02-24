package auth

import (
    "time"
    "sync"
    "errors"
)

type Session struct {
    UserID    string
    ExpiresAt time.Time
}

type SessionManager struct {
    sessions map[string]Session
    mu       sync.Mutex
}

func NewSessionManager() *SessionManager {
    return &SessionManager{
        sessions: make(map[string]Session),
    }
}

func (sm *SessionManager) CreateSession(userID string, duration time.Duration) (string, error) {
    sm.mu.Lock()
    defer sm.mu.Unlock()

    sessionID := generateSessionID()
    sm.sessions[sessionID] = Session{
        UserID:    userID,
        ExpiresAt: time.Now().Add(duration),
    }
    return sessionID, nil
}

func (sm *SessionManager) ValidateSession(sessionID string) (string, error) {
    sm.mu.Lock()
    defer sm.mu.Unlock()

    session, exists := sm.sessions[sessionID]
    if !exists || session.ExpiresAt.Before(time.Now()) {
        return "", errors.New("invalid or expired session")
    }
    return session.UserID, nil
}

func (sm *SessionManager) EndSession(sessionID string) {
    sm.mu.Lock()
    defer sm.mu.Unlock()

    delete(sm.sessions, sessionID)
}

func generateSessionID() string {
    // Implement a secure random session ID generator
    return "randomSessionID" // Placeholder
}
