package exporthandler

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/png"
	"strconv"
	"strings"
	"time"

	"github.com/jung-kurt/gofpdf"
)

// ExportRequest represents the parameters for exporting a signature
type ExportRequest struct {
	// Base64 encoded signature image data
	ImageData string
	// Export format: "png", "svg", or "pdf"
	Format string
	// Custom width in pixels (optional, defaults to original)
	Width int
	// Custom height in pixels (optional, defaults to original)
	Height int
	// Watermark text to overlay (optional)
	Watermark string
	// Metadata to embed (optional)
	Metadata map[string]string
}

// ExportResponse represents the exported signature data
type ExportResponse struct {
	// Exported data (base64 encoded for binary formats)
	Data string
	// Content type (e.g., "image/png", "image/svg+xml", "application/pdf")
	ContentType string
	// File extension
	Extension string
	// Size in bytes
	Size int
}

// ExportSignature exports a signature in the requested format
func ExportSignature(req ExportRequest) (*ExportResponse, error) {
	if req.ImageData == "" {
		return nil, errors.New("imageData is required")
	}

	// Validate and normalize format
	format := strings.ToLower(req.Format)
	switch format {
	case "png":
		return exportPNG(req)
	case "svg":
		return exportSVG(req)
	case "pdf":
		return exportPDF(req)
	default:
		return nil, fmt.Errorf("unsupported format: %s (supported: png, svg, pdf)", req.Format)
	}
}

// exportPNG exports the signature as PNG with custom dimensions
func exportPNG(req ExportRequest) (*ExportResponse, error) {
	// Decode base64 image data
	imgData, err := decodeBase64Image(req.ImageData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Decode to image.Image
	img, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode PNG: %w", err)
	}

	// TODO: Implement image resizing if custom dimensions are provided
	// For now, use original dimensions
	targetImg := img

	// TODO: Implement watermark overlay if provided
	// This is left for developer to implement

	// Encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, targetImg); err != nil {
		return nil, fmt.Errorf("failed to encode PNG: %w", err)
	}

	data := base64.StdEncoding.EncodeToString(buf.Bytes())

	return &ExportResponse{
		Data:        data,
		ContentType: "image/png",
		Extension:   "png",
		Size:        buf.Len(),
	}, nil
}

// exportSVG exports the signature as SVG with metadata
func exportSVG(req ExportRequest) (*ExportResponse, error) {
	// Decode base64 image data to get dimensions
	imgData, err := decodeBase64Image(req.ImageData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	img, _, err := image.Decode(bytes.NewReader(imgData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	bounds := img.Bounds()
	width := req.Width
	height := req.Height
	if width == 0 {
		width = bounds.Dx()
	}
	if height == 0 {
		height = bounds.Dy()
	}

	// Build SVG with embedded PNG as base64
	var svg strings.Builder
	svg.WriteString(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg width="%d" height="%d" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
`, width, height))

	// Add metadata if provided
	if len(req.Metadata) > 0 {
		svg.WriteString("  <metadata>\n")
		svg.WriteString("    <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\n")
		for key, value := range req.Metadata {
			svg.WriteString(fmt.Sprintf("      <rdf:Description rdf:about=\"\" dc:%s=\"%s\"/>\n", key, value))
		}
		svg.WriteString(fmt.Sprintf("      <rdf:Description rdf:about=\"\" dc:created=\"%s\"/>\n", time.Now().Format(time.RFC3339)))
		svg.WriteString("    </rdf:RDF>\n")
		svg.WriteString("  </metadata>\n")
	}

	// Embed the image
	svg.WriteString(fmt.Sprintf("  <image xlink:href=\"data:image/png;base64,%s\" width=\"%d\" height=\"%d\"/>\n",
		base64.StdEncoding.EncodeToString(imgData), width, height))

	// Add watermark if provided
	if req.Watermark != "" {
		svg.WriteString(fmt.Sprintf("  <text x=\"%d\" y=\"%d\" font-size=\"12\" fill=\"rgba(128,128,128,0.5)\" text-anchor=\"middle\">%s</text>\n",
			width/2, height-10, req.Watermark))
	}

	svg.WriteString("</svg>")

	return &ExportResponse{
		Data:        svg.String(),
		ContentType: "image/svg+xml",
		Extension:   "svg",
		Size:        svg.Len(),
	}, nil
}

// exportPDF exports the signature as PDF (basic implementation - developer to enhance)
func exportPDF(req ExportRequest) (*ExportResponse, error) {
	// Decode base64 image data
	imgData, err := decodeBase64Image(req.ImageData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode image: %w", err)
	}

	// Create new PDF
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.AddPage()

	// TODO: Developer should enhance this with:
	// - Custom page sizes based on signature dimensions
	// - Better image positioning and scaling
	// - Watermark overlay
	// - Metadata embedding in PDF properties
	// - Digital signature support

	// For now, create a basic PDF with the signature
	// We need to save the image temporarily or use RegisterImageReader
	imgReader := bytes.NewReader(imgData)
	opts := gofpdf.ImageOptions{
		ImageType: "PNG",
		ReadDpi:   true,
	}

	// Register the image
	pdf.RegisterImageOptionsReader("signature", opts, imgReader)

	// Calculate dimensions (basic implementation)
	width := float64(req.Width)
	height := float64(req.Height)
	if width == 0 || height == 0 {
		// Default size
		width = 100
		height = 50
	}

	// Convert pixels to mm (rough approximation: 96 DPI)
	widthMM := width * 0.264583
	heightMM := height * 0.264583

	// Center the image
	pageWidth, _ := pdf.GetPageSize()
	x := (pageWidth - widthMM) / 2

	pdf.ImageOptions("signature", x, 20, widthMM, heightMM, false, opts, 0, "")

	// Add watermark if provided
	if req.Watermark != "" {
		pdf.SetFont("Arial", "I", 10)
		pdf.SetTextColor(128, 128, 128)
		pdf.Text(x, 20+heightMM+10, req.Watermark)
	}

	// Add metadata
	if len(req.Metadata) > 0 {
		if title, ok := req.Metadata["title"]; ok {
			pdf.SetTitle(title, true)
		}
		if author, ok := req.Metadata["author"]; ok {
			pdf.SetAuthor(author, true)
		}
		if subject, ok := req.Metadata["subject"]; ok {
			pdf.SetSubject(subject, true)
		}
	}
	pdf.SetCreator("Signature Export API", true)
	pdf.SetCreationDate(time.Now())

	// Generate PDF bytes
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}

	data := base64.StdEncoding.EncodeToString(buf.Bytes())

	return &ExportResponse{
		Data:        data,
		ContentType: "application/pdf",
		Extension:   "pdf",
		Size:        buf.Len(),
	}, nil
}

// decodeBase64Image decodes base64 image data, handling data URL format
func decodeBase64Image(imageData string) ([]byte, error) {
	// Remove data URL prefix if present (e.g., "data:image/png;base64,")
	if strings.Contains(imageData, ",") {
		parts := strings.SplitN(imageData, ",", 2)
		if len(parts) == 2 {
			imageData = parts[1]
		}
	}

	return base64.StdEncoding.DecodeString(imageData)
}

// ParseExportRequestFromQuery parses export request from query string parameters
func ParseExportRequestFromQuery(params map[string]string) (ExportRequest, error) {
	req := ExportRequest{
		Metadata: make(map[string]string),
	}

	// Required: imageData
	imageData, ok := params["imageData"]
	if !ok || imageData == "" {
		return req, errors.New("imageData parameter is required")
	}
	req.ImageData = imageData

	// Required: format
	format, ok := params["format"]
	if !ok || format == "" {
		return req, errors.New("format parameter is required")
	}
	req.Format = format

	// Optional: width
	if width, ok := params["width"]; ok && width != "" {
		w, err := strconv.Atoi(width)
		if err != nil {
			return req, fmt.Errorf("invalid width parameter: %w", err)
		}
		req.Width = w
	}

	// Optional: height
	if height, ok := params["height"]; ok && height != "" {
		h, err := strconv.Atoi(height)
		if err != nil {
			return req, fmt.Errorf("invalid height parameter: %w", err)
		}
		req.Height = h
	}

	// Optional: watermark
	if watermark, ok := params["watermark"]; ok {
		req.Watermark = watermark
	}

	// Optional: metadata (e.g., metadata_author, metadata_title)
	for key, value := range params {
		if strings.HasPrefix(key, "metadata_") {
			metaKey := strings.TrimPrefix(key, "metadata_")
			req.Metadata[metaKey] = value
		}
	}

	return req, nil
}
