package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// SignatureHandler handles all signature-related operations
type SignatureHandler struct {
	signatureService SignatureService
}

// NewSignatureHandler creates a new instance of SignatureHandler
func NewSignatureHandler(service SignatureService) *SignatureHandler {
	return &SignatureHandler{
		signatureService: service,
	}
}

// SignatureInput represents the input for creating a signature
type SignatureInput struct {
	UserID        string                 `json:"userId"`
	SignatureData string                 `json:"signatureData"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// Signature represents a complete signature record
type Signature struct {
	ID            string                 `json:"id"`
	UserID        string                 `json:"userId"`
	SignatureData string                 `json:"signatureData"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt     time.Time             `json:"createdAt"`
	LastUsed      *time.Time            `json:"lastUsed,omitempty"`
}

// SignatureVerificationRequest represents a request to verify a signature
type SignatureVerificationRequest struct {
	SignatureID   string `json:"signatureId"`
	DocumentHash  string `json:"documentHash"`
}

// SignatureVerificationResult represents the result of signature verification
type SignatureVerificationResult struct {
	IsValid              bool      `json:"isValid"`
	VerificationTimestamp time.Time `json:"verificationTimestamp"`
	Details              struct {
		ConfidenceScore  float64  `json:"confidenceScore,omitempty"`
		MatchedFeatures  []string `json:"matchedFeatures,omitempty"`
	} `json:"details,omitempty"`
}

// CreateSignature handles the creation of a new signature
func (h *SignatureHandler) CreateSignature(w http.ResponseWriter, r *http.Request) {
	var input SignatureInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	signature, err := h.signatureService.CreateSignature(r.Context(), input)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(signature)
}

// ListSignatures handles retrieving all signatures for a user
func (h *SignatureHandler) ListSignatures(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("userId")
	if userID == "" {
		http.Error(w, "userId is required", http.StatusBadRequest)
		return
	}

	limit := 20 // default limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 50 {
			limit = l
		}
	}

	signatures, err := h.signatureService.ListSignatures(r.Context(), userID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signatures)
}

// GetSignature handles retrieving a specific signature
func (h *SignatureHandler) GetSignature(w http.ResponseWriter, r *http.Request) {
	signatureID := r.URL.Query().Get("signatureId")
	if signatureID == "" {
		http.Error(w, "signatureId is required", http.StatusBadRequest)
		return
	}

	signature, err := h.signatureService.GetSignature(r.Context(), signatureID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(signature)
}

// DeleteSignature handles deleting a signature
func (h *SignatureHandler) DeleteSignature(w http.ResponseWriter, r *http.Request) {
	signatureID := r.URL.Query().Get("signatureId")
	if signatureID == "" {
		http.Error(w, "signatureId is required", http.StatusBadRequest)
		return
	}

	if err := h.signatureService.DeleteSignature(r.Context(), signatureID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// VerifySignature handles signature verification requests
func (h *SignatureHandler) VerifySignature(w http.ResponseWriter, r *http.Request) {
	var req SignatureVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	result, err := h.signatureService.VerifySignature(r.Context(), req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// SignatureService defines the interface for signature operations
type SignatureService interface {
	CreateSignature(ctx context.Context, input SignatureInput) (*Signature, error)
	ListSignatures(ctx context.Context, userID string, limit int) ([]Signature, error)
	GetSignature(ctx context.Context, signatureID string) (*Signature, error)
	DeleteSignature(ctx context.Context, signatureID string) error
	VerifySignature(ctx context.Context, req SignatureVerificationRequest) (*SignatureVerificationResult, error)
}