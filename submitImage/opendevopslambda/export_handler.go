package opendevopslambda

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"submit-image/exporthandler"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
)

// ExportHandlerResponse is the structured response for export operations
type ExportHandlerResponse struct {
	SignatureID  string `json:"signatureId"`
	Format       string `json:"format"`
	ContentType  string `json:"contentType"`
	DataURL      string `json:"dataUrl"`
	Size         int    `json:"size"`
	Timestamp    string `json:"timestamp"`
	StorageURL   string `json:"storageUrl,omitempty"`
}

// ExportSignatureHandler handles signature export requests
// Path: /export
// Methods: POST
func (d *Dependency) ExportSignatureHandler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	// Set CORS headers
	headers := map[string]string{
		"Content-Type":                "application/json",
		"Access-Control-Allow-Origin": "*",
		"Access-Control-Allow-Methods": "POST, OPTIONS",
		"Access-Control-Allow-Headers": "Content-Type",
	}

	// Handle preflight requests
	if request.HTTPMethod == "OPTIONS" {
		return events.APIGatewayProxyResponse{
			StatusCode: 200,
			Headers:    headers,
			Body:       "",
		}, nil
	}

	// Parse request body
	var reqBody map[string]interface{}
	if err := json.Unmarshal([]byte(request.Body), &reqBody); err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Headers:    headers,
			Body:       jsonError("INVALID_REQUEST", "request body is not valid JSON"),
		}, nil
	}

	// Extract required parameters
	imageData, ok := reqBody["imageData"].(string)
	if !ok || imageData == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Headers:    headers,
			Body:       jsonError("MISSING_PARAMETER", "imageData is required"),
		}, nil
	}

	format, ok := reqBody["format"].(string)
	if !ok || format == "" {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Headers:    headers,
			Body:       jsonError("MISSING_PARAMETER", "format is required (png, svg, or pdf)"),
		}, nil
	}

	// Build export request
	exportReq := exporthandler.ExportRequest{
		ImageData: imageData,
		Format:    format,
	}

	// Optional parameters
	if width, ok := reqBody["width"].(float64); ok && width > 0 {
		exportReq.Width = int(width)
	}

	if height, ok := reqBody["height"].(float64); ok && height > 0 {
		exportReq.Height = int(height)
	}

	if watermark, ok := reqBody["watermark"].(string); ok {
		exportReq.Watermark = watermark
	}

	// Extract metadata if provided
	if metadata, ok := reqBody["metadata"].(map[string]interface{}); ok {
		exportReq.Metadata = make(map[string]string)
		for key, value := range metadata {
			if strVal, ok := value.(string); ok {
				exportReq.Metadata[key] = strVal
			}
		}
	}

	// Export signature
	exportResp, err := exporthandler.ExportSignature(exportReq)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Headers:    headers,
			Body:       jsonError("EXPORT_FAILED", fmt.Sprintf("failed to export signature: %v", err)),
		}, nil
	}

	// Create response
	resp := ExportHandlerResponse{
		SignatureID: generateSignatureID(),
		Format:      format,
		ContentType: exportResp.ContentType,
		DataURL:     fmt.Sprintf("data:%s;base64,%s", exportResp.ContentType, exportResp.Data),
		Size:        exportResp.Size,
		Timestamp:   getTimestamp(),
	}

	// Optionally store in S3 if requested
	if storeInS3, ok := reqBody["storeInS3"].(bool); ok && storeInS3 {
		storageURL, err := d.storeExportedSignature(ctx, exportResp, format)
		if err != nil {
			// Log error but don't fail the request
			fmt.Printf("Warning: failed to store in S3: %v\n", err)
		} else {
			resp.StorageURL = storageURL
		}
	}

	// Return response
	body, _ := json.Marshal(resp)
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Headers:    headers,
		Body:       string(body),
	}, nil
}

// storeExportedSignature stores the exported signature in S3
func (d *Dependency) storeExportedSignature(ctx context.Context, exportResp *exporthandler.ExportResponse, format string) (string, error) {
	if d.DepS3 == nil {
		return "", errors.New("S3 dependency not configured")
	}

	// Decode base64 data for binary formats
	var data []byte
	var err error
	if format == "svg" {
		// SVG is text, no need to decode
		data = []byte(exportResp.Data)
	} else {
		// PNG and PDF are base64 encoded
		data, err = base64.StdEncoding.DecodeString(exportResp.Data)
		if err != nil {
			return "", fmt.Errorf("failed to decode export data: %w", err)
		}
	}

	// Generate S3 key
	key := fmt.Sprintf("exports/%s.%s", generateSignatureID(), exportResp.Extension)

	// Put object in S3
	input := &s3.PutObjectInput{
		Body:        strings.NewReader(string(data)),
		Bucket:      aws.String("exported-signatures"),
		Key:         aws.String(key),
		ContentType: aws.String(exportResp.ContentType),
		Metadata: map[string]*string{
			"format":    aws.String(format),
			"timestamp": aws.String(getTimestamp()),
		},
	}

	_, err = d.DepS3.PutObject(input)
	if err != nil {
		return "", err
	}

	// Return S3 URL
	return fmt.Sprintf("s3://exported-signatures/%s", key), nil
}

// jsonError creates a JSON error response
func jsonError(errorCode string, message string) string {
	resp := map[string]string{
		"error":   errorCode,
		"message": message,
	}
	body, _ := json.Marshal(resp)
	return string(body)
}

// generateSignatureID generates a unique signature ID
func generateSignatureID() string {
	return fmt.Sprintf("sig_%d", getCurrentTimestampMillis())
}

// getTimestamp returns current timestamp in RFC3339 format
func getTimestamp() string {
	return getCurrentTime().Format("2006-01-02T15:04:05Z07:00")
}

// getCurrentTimestampMillis returns current timestamp in milliseconds
func getCurrentTimestampMillis() int64 {
	return getCurrentTime().UnixNano() / 1e6
}

// getCurrentTime returns current time (can be mocked in tests)
func getCurrentTime() time.Time {
	return time.Now()
}
