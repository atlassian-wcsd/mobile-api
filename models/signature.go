package models

import (
	"time"
)

// Signature represents a mobile handwriting signature
type Signature struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	UserID      uint      `gorm:"not null" json:"user_id"`
	ImageData   []byte    `gorm:"type:bytea;not null" json:"image_data"`
	Metadata    string    `gorm:"type:jsonb" json:"metadata"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Description string    `json:"description"`
}

// SignatureMetadata represents additional information about the signature
type SignatureMetadata struct {
	DeviceInfo struct {
		Type     string `json:"type"`      // e.g., "smartphone", "tablet"
		Model    string `json:"model"`     // Device model
		Platform string `json:"platform"`  // OS platform
	} `json:"device_info"`
	
	Dimensions struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	} `json:"dimensions"`
	
	Properties struct {
		PressureSensitive bool    `json:"pressure_sensitive"` // Whether pressure data was captured
		StrokeCount       int     `json:"stroke_count"`       // Number of strokes in signature
		Duration          float64 `json:"duration"`           // Time taken to complete signature (seconds)
	} `json:"properties"`
	
	Location struct {
		Latitude  float64 `json:"latitude,omitempty"`
		Longitude float64 `json:"longitude,omitempty"`
	} `json:"location,omitempty"`
}

// TableName specifies the table name for the Signature model
func (Signature) TableName() string {
	return "signatures"
}