package models

import "time"

// Feedback represents user feedback entry in the database
type Feedback struct {
	ID            string                 `json:"id" dynamodbav:"Id"`
	UserID        string                 `json:"userId" dynamodbav:"UserId"`
	FeedbackType  string                 `json:"feedbackType" dynamodbav:"FeedbackType"`
	Rating        *int                   `json:"rating,omitempty" dynamodbav:"Rating,omitempty"`
	Title         string                 `json:"title" dynamodbav:"Title"`
	Message       string                 `json:"message" dynamodbav:"Message"`
	Category      string                 `json:"category" dynamodbav:"Category"`
	PageContext   string                 `json:"pageContext,omitempty" dynamodbav:"PageContext,omitempty"`
	UserAgent     string                 `json:"userAgent,omitempty" dynamodbav:"UserAgent,omitempty"`
	DeviceInfo    *DeviceInfo            `json:"deviceInfo,omitempty" dynamodbav:"DeviceInfo,omitempty"`
	CreatedAt     time.Time              `json:"createdAt" dynamodbav:"CreatedAt"`
	Status        string                 `json:"status" dynamodbav:"Status"`
	Email         string                 `json:"email,omitempty" dynamodbav:"Email,omitempty"`
	AllowContact  bool                   `json:"allowContact" dynamodbav:"AllowContact"`
	AttachmentIDs []string               `json:"attachmentIds,omitempty" dynamodbav:"AttachmentIds,omitempty"`
	AdminNotes    string                 `json:"adminNotes,omitempty" dynamodbav:"AdminNotes,omitempty"`
	UpdatedAt     *time.Time             `json:"updatedAt,omitempty" dynamodbav:"UpdatedAt,omitempty"`
}

// DeviceInfo contains device-specific information
type DeviceInfo struct {
	Platform         string `json:"platform" dynamodbav:"Platform"`
	Browser          string `json:"browser" dynamodbav:"Browser"`
	ScreenResolution string `json:"screenResolution" dynamodbav:"ScreenResolution"`
	IsMobile         bool   `json:"isMobile" dynamodbav:"IsMobile"`
}

// FeedbackSubmitRequest represents the request to submit feedback
type FeedbackSubmitRequest struct {
	FeedbackType  string   `json:"feedbackType" validate:"required,oneof=bug feature improvement general"`
	Rating        *int     `json:"rating,omitempty" validate:"omitempty,min=1,max=5"`
	Title         string   `json:"title" validate:"required,min=3,max=200"`
	Message       string   `json:"message" validate:"required,min=10,max=5000"`
	Category      string   `json:"category" validate:"required"`
	PageContext   string   `json:"pageContext,omitempty"`
	Email         string   `json:"email,omitempty" validate:"omitempty,email"`
	AllowContact  bool     `json:"allowContact"`
	AttachmentIDs []string `json:"attachmentIds,omitempty"`
}

// FeedbackSubmitResponse represents the response after submitting feedback
type FeedbackSubmitResponse struct {
	Success    bool   `json:"success"`
	FeedbackID string `json:"feedbackId,omitempty"`
	Message    string `json:"message"`
	Error      string `json:"error,omitempty"`
}

// UserMetric represents analytics/metrics data
type UserMetric struct {
	ID         string                 `json:"id" dynamodbav:"Id"`
	UserID     string                 `json:"userId" dynamodbav:"UserId"`
	EventType  string                 `json:"eventType" dynamodbav:"EventType"`
	EventName  string                 `json:"eventName" dynamodbav:"EventName"`
	Properties map[string]interface{} `json:"properties,omitempty" dynamodbav:"Properties,omitempty"`
	SessionID  string                 `json:"sessionId,omitempty" dynamodbav:"SessionId,omitempty"`
	Page       string                 `json:"page,omitempty" dynamodbav:"Page,omitempty"`
	Duration   *int64                 `json:"duration,omitempty" dynamodbav:"Duration,omitempty"`
	Timestamp  time.Time              `json:"timestamp" dynamodbav:"Timestamp"`
	Context    *MetricContext         `json:"context,omitempty" dynamodbav:"Context,omitempty"`
	Geo        *GeoInfo               `json:"geo,omitempty" dynamodbav:"Geo,omitempty"`
}

// MetricContext contains contextual information about the metric
type MetricContext struct {
	UserAgent        string `json:"userAgent" dynamodbav:"UserAgent"`
	Platform         string `json:"platform" dynamodbav:"Platform"`
	Browser          string `json:"browser" dynamodbav:"Browser"`
	ScreenResolution string `json:"screenResolution" dynamodbav:"ScreenResolution"`
	Viewport         string `json:"viewport" dynamodbav:"Viewport"`
	IsMobile         bool   `json:"isMobile" dynamodbav:"IsMobile"`
	IsTablet         bool   `json:"isTablet" dynamodbav:"IsTablet"`
}

// GeoInfo contains geographic information
type GeoInfo struct {
	Country string `json:"country,omitempty" dynamodbav:"Country,omitempty"`
	Region  string `json:"region,omitempty" dynamodbav:"Region,omitempty"`
	City    string `json:"city,omitempty" dynamodbav:"City,omitempty"`
}

// MetricTrackRequest represents the request to track a metric
type MetricTrackRequest struct {
	EventType  string                 `json:"eventType" validate:"required"`
	EventName  string                 `json:"eventName" validate:"required"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	SessionID  string                 `json:"sessionId,omitempty"`
	Page       string                 `json:"page,omitempty"`
	Duration   *int64                 `json:"duration,omitempty"`
}

// MetricTrackResponse represents the response after tracking a metric
type MetricTrackResponse struct {
	Success  bool   `json:"success"`
	MetricID string `json:"metricId,omitempty"`
	Message  string `json:"message"`
	Error    string `json:"error,omitempty"`
}

// MetricsSummary represents aggregated metrics
type MetricsSummary struct {
	TotalEvents            int                       `json:"totalEvents"`
	UniqueUsers            int                       `json:"uniqueUsers"`
	EventsByType           map[string]int            `json:"eventsByType"`
	AverageSessionDuration float64                   `json:"averageSessionDuration"`
	TopPages               []PageView                `json:"topPages"`
	DeviceBreakdown        DeviceBreakdown           `json:"deviceBreakdown"`
	TimeRange              TimeRange                 `json:"timeRange"`
}

// PageView represents page view statistics
type PageView struct {
	Page  string `json:"page"`
	Views int    `json:"views"`
}

// DeviceBreakdown represents device type statistics
type DeviceBreakdown struct {
	Mobile  int `json:"mobile"`
	Tablet  int `json:"tablet"`
	Desktop int `json:"desktop"`
}

// TimeRange represents a time range for metrics
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
