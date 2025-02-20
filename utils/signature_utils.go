package utils

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"time"
)

// SignatureData represents the data structure for a mobile handwriting signature
type SignatureData struct {
	Points     []Point   `json:"points"`
	Timestamp  time.Time `json:"timestamp"`
	DeviceInfo string    `json:"deviceInfo"`
}

// Point represents a single point in the signature with pressure information
type Point struct {
	X        float64 `json:"x"`
	Y        float64 `json:"y"`
	Pressure float64 `json:"pressure"`
}

// CreateSignature creates a new SignatureData instance with the given points and device info
func CreateSignature(points []Point, deviceInfo string) SignatureData {
	return SignatureData{
		Points:     points,
		Timestamp:  time.Now(),
		DeviceInfo: deviceInfo,
	}
}

// ConvertToImage converts the signature data to a PNG image
func (s *SignatureData) ConvertToImage(width, height int) (string, error) {
	img := image.NewRGBA(image.Rect(0, 0, width, height))

	// Draw the signature on the image
	for i := 1; i < len(s.Points); i++ {
		p1 := s.Points[i-1]
		p2 := s.Points[i]
		
		// Simple line drawing between points
		drawLine(img, int(p1.X), int(p1.Y), int(p2.X), int(p2.Y))
	}

	// Convert image to base64
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// ValidateSignature checks if the signature data is valid
func (s *SignatureData) ValidateSignature() bool {
	// Basic validation rules
	if len(s.Points) < 2 {
		return false
	}

	if s.DeviceInfo == "" {
		return false
	}

	if s.Timestamp.IsZero() {
		return false
	}

	return true
}

// drawLine implements Bresenham's line algorithm
func drawLine(img *image.RGBA, x1, y1, x2, y2 int) {
	dx := abs(x2 - x1)
	dy := abs(y2 - y1)
	steep := dy > dx

	if steep {
		x1, y1 = y1, x1
		x2, y2 = y2, x2
	}
	if x1 > x2 {
		x1, x2 = x2, x1
		y1, y2 = y2, y1
	}

	dx = x2 - x1
	dy = abs(y2 - y1)
	err := dx / 2
	ystep := 1
	if y1 >= y2 {
		ystep = -1
	}

	for x := x1; x <= x2; x++ {
		if steep {
			img.Set(y1, x, image.Black)
		} else {
			img.Set(x, y1, image.Black)
		}
		err -= dy
		if err < 0 {
			y1 += ystep
			err += dx
		}
	}
}

// abs returns the absolute value of x
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}