package auth

import (
	"time"
	"errors"
)

// Session represents a user session
type Session struct {
	UserID    string
	ExpiresAt time.Time
}

// SessionManager handles user sessions
type SessionManager struct {
	sessions map[string]Session
}

// NewSessionManager creates a new SessionManager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]Session),
	}
}

// CreateSession creates a new session for a user
func (sm *SessionManager) CreateSession(userID string, duration time.Duration) (string, error) {
	sessionID := generateSessionID()
	expiresAt := time.Now().Add(duration)
	sm.sessions[sessionID] = Session{
		UserID:    userID,
		ExpiresAt: expiresAt,
	}
	return sessionID, nil
}

// GetSession retrieves a session by its ID
func (sm *SessionManager) GetSession(sessionID string) (Session, error) {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return Session{}, errors.New("session not found")
	}
	if session.ExpiresAt.Before(time.Now()) {
		delete(sm.sessions, sessionID)
		return Session{}, errors.New("session expired")
	}
	return session, nil
}

// DeleteSession removes a session by its ID
func (sm *SessionManager) DeleteSession(sessionID string) {
	delete(sm.sessions, sessionID)
}

// generateSessionID generates a new session ID
func generateSessionID() string {
	// Implement a secure random session ID generator
	return "randomSessionID"
}
