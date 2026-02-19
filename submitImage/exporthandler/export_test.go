package exporthandler

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test helper to create a simple base64 encoded PNG
func getTestImageData() string {
	// This is a minimal 1x1 pixel PNG (red pixel)
	pngBytes := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
		0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
		0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
		0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
		0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
		0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
		0x44, 0xAE, 0x42, 0x60, 0x82,
	}
	return base64.StdEncoding.EncodeToString(pngBytes)
}

func TestExportSignature_PNG(t *testing.T) {
	req := ExportRequest{
		ImageData: getTestImageData(),
		Format:    "png",
		Width:     100,
		Height:    100,
	}

	resp, err := ExportSignature(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "image/png", resp.ContentType)
	assert.Equal(t, "png", resp.Extension)
	assert.Greater(t, resp.Size, 0)
	assert.NotEmpty(t, resp.Data)
}

func TestExportSignature_SVG(t *testing.T) {
	req := ExportRequest{
		ImageData: getTestImageData(),
		Format:    "svg",
		Width:     200,
		Height:    100,
		Watermark: "Test Watermark",
		Metadata: map[string]string{
			"author": "Test Author",
			"title":  "Test Signature",
		},
	}

	resp, err := ExportSignature(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "image/svg+xml", resp.ContentType)
	assert.Equal(t, "svg", resp.Extension)
	assert.Greater(t, resp.Size, 0)
	
	// Verify SVG content
	assert.Contains(t, resp.Data, "<?xml version")
	assert.Contains(t, resp.Data, "<svg")
	assert.Contains(t, resp.Data, "width=\"200\"")
	assert.Contains(t, resp.Data, "height=\"100\"")
	assert.Contains(t, resp.Data, "Test Watermark")
	assert.Contains(t, resp.Data, "<metadata>")
}

func TestExportSignature_PDF(t *testing.T) {
	req := ExportRequest{
		ImageData: getTestImageData(),
		Format:    "pdf",
		Width:     150,
		Height:    75,
		Watermark: "Confidential",
		Metadata: map[string]string{
			"author":  "John Doe",
			"title":   "Signature Document",
			"subject": "Legal Signature",
		},
	}

	resp, err := ExportSignature(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "application/pdf", resp.ContentType)
	assert.Equal(t, "pdf", resp.Extension)
	assert.Greater(t, resp.Size, 0)
	assert.NotEmpty(t, resp.Data)

	// Decode and verify it's a valid PDF
	pdfData, err := base64.StdEncoding.DecodeString(resp.Data)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pdfData), "%PDF"))
}

func TestExportSignature_InvalidFormat(t *testing.T) {
	req := ExportRequest{
		ImageData: getTestImageData(),
		Format:    "invalid",
	}

	resp, err := ExportSignature(req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "unsupported format")
}

func TestExportSignature_MissingImageData(t *testing.T) {
	req := ExportRequest{
		ImageData: "",
		Format:    "png",
	}

	resp, err := ExportSignature(req)
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "imageData is required")
}

func TestExportSignature_WithDataURLPrefix(t *testing.T) {
	// Test with data URL format
	req := ExportRequest{
		ImageData: "data:image/png;base64," + getTestImageData(),
		Format:    "png",
	}

	resp, err := ExportSignature(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "image/png", resp.ContentType)
}

func TestDecodeBase64Image(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "Valid base64",
			input:     getTestImageData(),
			wantError: false,
		},
		{
			name:      "Valid base64 with data URL prefix",
			input:     "data:image/png;base64," + getTestImageData(),
			wantError: false,
		},
		{
			name:      "Invalid base64",
			input:     "!!!invalid!!!",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := decodeBase64Image(tt.input)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, data)
			}
		})
	}
}

func TestParseExportRequestFromQuery(t *testing.T) {
	tests := []struct {
		name      string
		params    map[string]string
		wantError bool
		validate  func(*testing.T, ExportRequest)
	}{
		{
			name: "Valid request with all parameters",
			params: map[string]string{
				"imageData":        getTestImageData(),
				"format":           "png",
				"width":            "200",
				"height":           "100",
				"watermark":        "Test",
				"metadata_author":  "John",
				"metadata_title":   "Signature",
			},
			wantError: false,
			validate: func(t *testing.T, req ExportRequest) {
				assert.Equal(t, "png", req.Format)
				assert.Equal(t, 200, req.Width)
				assert.Equal(t, 100, req.Height)
				assert.Equal(t, "Test", req.Watermark)
				assert.Equal(t, "John", req.Metadata["author"])
				assert.Equal(t, "Signature", req.Metadata["title"])
			},
		},
		{
			name: "Missing imageData",
			params: map[string]string{
				"format": "png",
			},
			wantError: true,
		},
		{
			name: "Missing format",
			params: map[string]string{
				"imageData": getTestImageData(),
			},
			wantError: true,
		},
		{
			name: "Invalid width",
			params: map[string]string{
				"imageData": getTestImageData(),
				"format":    "png",
				"width":     "invalid",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := ParseExportRequestFromQuery(tt.params)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, req)
				}
			}
		})
	}
}

func TestExportSignature_SVGWithoutMetadata(t *testing.T) {
	req := ExportRequest{
		ImageData: getTestImageData(),
		Format:    "svg",
		Width:     100,
		Height:    100,
	}

	resp, err := ExportSignature(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	
	// Should not contain metadata section when no metadata provided
	assert.NotContains(t, resp.Data, "<metadata>")
}

func TestExportSignature_DefaultDimensions(t *testing.T) {
	// Test that export works without specifying dimensions
	req := ExportRequest{
		ImageData: getTestImageData(),
		Format:    "png",
		// Width and Height are 0 (not specified)
	}

	resp, err := ExportSignature(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "image/png", resp.ContentType)
}
