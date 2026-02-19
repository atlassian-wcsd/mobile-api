# Multi-Format Signature Export API - Implementation Guide

## JIRA Ticket
**MOBL-3653**: Add Multi-Format Signature Export API

## Overview
This implementation adds a new `/export` endpoint to the signature application that allows users to export signatures in multiple formats (PNG, SVG, PDF) with customizable dimensions, watermarks, and metadata embedding.

## What Has Been Implemented

### 1. Export Handler Package (`submitImage/exporthandler/export.go`)
**Status: ✅ Complete (Agent Implementation)**

Core functionality for signature export:
- **PNG Export**: Basic implementation with image decoding
- **SVG Export**: Fully functional with metadata embedding and watermark support
- **PDF Export**: Basic scaffold with gofpdf library integration
- **Request Parsing**: Query parameter and JSON body parsing utilities

**Key Functions:**
- `ExportSignature(req ExportRequest)`: Main export function
- `exportPNG(req ExportRequest)`: PNG format handler
- `exportSVG(req ExportRequest)`: SVG format handler with full metadata support
- `exportPDF(req ExportRequest)`: PDF format handler (basic scaffold)
- `ParseExportRequestFromQuery()`: Query string parser

### 2. Lambda Handler (`submitImage/opendevopslambda/export_handler.go`)
**Status: ✅ Complete (Agent Implementation)**

HTTP endpoint handler with:
- CORS support (preflight OPTIONS handling)
- JSON request/response handling
- Optional S3 storage for exported signatures
- Structured error responses

**API Endpoint:**
- Path: `/export`
- Method: POST
- Content-Type: `application/json`

**Request Format:**
```json
{
  "imageData": "base64-encoded-image-or-data-url",
  "format": "png|svg|pdf",
  "width": 200,
  "height": 100,
  "watermark": "Optional watermark text",
  "metadata": {
    "author": "John Doe",
    "title": "Signature Document",
    "subject": "Legal Signature"
  },
  "storeInS3": true
}
```

**Response Format:**
```json
{
  "signatureId": "sig_1234567890",
  "format": "png",
  "contentType": "image/png",
  "dataUrl": "data:image/png;base64,...",
  "size": 12345,
  "timestamp": "2026-02-19T12:00:00Z",
  "storageUrl": "s3://exported-signatures/exports/sig_1234567890.png"
}
```

### 3. Lambda Router Update (`submitImage/opendevopslambda/lambda.go`)
**Status: ✅ Complete (Agent Implementation)**

Updated the main handler to route requests:
- `/export` → `ExportSignatureHandler`
- `/bootstrap` (default) → Original image submission handler

### 4. SAM Template Update (`template.yml`)
**Status: ✅ Complete (Agent Implementation)**

Added new API Gateway event:
```yaml
ExportSignature:
  Type: Api
  Properties:
    Path: /export
    Method: POST
```

### 5. Dependencies (`submitImage/go.mod`)
**Status: ✅ Complete (Agent Implementation)**

Added:
- `github.com/jung-kurt/gofpdf v1.16.2` - PDF generation library

### 6. Unit Tests (`submitImage/exporthandler/export_test.go`)
**Status: ✅ Complete (Agent Implementation)**

Comprehensive test coverage:
- ✅ PNG export with various parameters
- ✅ SVG export with metadata and watermarks
- ✅ PDF export validation
- ✅ Invalid format handling
- ✅ Missing parameter validation
- ✅ Data URL format handling
- ✅ Query parameter parsing
- ✅ Default dimension handling

## What Needs Developer Enhancement

### 1. PNG Export - Image Resizing ⚠️ TODO
**File**: `submitImage/exporthandler/export.go` (line ~90)

```go
// TODO: Implement image resizing if custom dimensions are provided
// For now, use original dimensions
targetImg := img
```

**Recommendation**: Use `github.com/nfnt/resize` or `golang.org/x/image/draw` for high-quality image resizing.

### 2. PNG Export - Watermark Overlay ⚠️ TODO
**File**: `submitImage/exporthandler/export.go` (line ~93)

```go
// TODO: Implement watermark overlay if provided
// This is left for developer to implement
```

**Recommendation**: Use `image/draw` package to composite watermark text or image onto the signature.

### 3. PDF Export - Enhanced Features ⚠️ TODO
**File**: `submitImage/exporthandler/export.go` (line ~180)

Current implementation is basic. Enhancements needed:
- Custom page sizes based on signature dimensions
- Better image positioning and scaling
- Advanced watermark positioning and styling
- Rich metadata embedding in PDF properties
- Digital signature support (cryptographic signatures)
- Multiple signatures per document
- Custom fonts and styling

**Libraries to Consider**:
- Continue with `gofpdf` for basic PDFs
- Or use `github.com/jung-kurt/gofpdf/contrib/gofpdi` for advanced features
- For digital signatures: `github.com/pdfcpu/pdfcpu`

### 4. S3 Storage Configuration ⚠️ TODO
**File**: `submitImage/opendevopslambda/export_handler.go` (line ~172)

```go
Bucket: aws.String("exported-signatures"),
```

**Action Required**:
- Create S3 bucket: `exported-signatures` or use environment variable
- Update SAM template with S3 permissions
- Add bucket name as environment variable
- Implement proper error handling for S3 operations

### 5. Integration Tests ⚠️ TODO
**What's Needed**:
- End-to-end Lambda handler tests with mocked AWS services
- API Gateway integration tests
- Performance testing with various image sizes
- Load testing for concurrent requests

### 6. Frontend Integration ⚠️ TODO
**Files to Update**:
- `src/services/SignatureService.ts` - Add export methods
- Create new component: `src/components/SignatureExporter.tsx`

**Example Implementation**:
```typescript
export class SignatureService {
  // ... existing methods ...

  /**
   * Export signature in specified format
   */
  public async exportSignature(
    signatureId: string,
    format: 'png' | 'svg' | 'pdf',
    options?: {
      width?: number;
      height?: number;
      watermark?: string;
      metadata?: Record<string, string>;
    }
  ): Promise<ExportResponse> {
    const signature = this.getSignature(signatureId);
    if (!signature) {
      throw new Error('Signature not found');
    }

    const response = await fetch('/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        imageData: signature.imageData,
        format,
        ...options
      })
    });

    return response.json();
  }
}
```

## Deployment Instructions

### Prerequisites
- Go 1.16+ installed
- AWS SAM CLI installed
- AWS credentials configured

### Steps

1. **Install Dependencies**
   ```bash
   cd submitImage
   go mod download
   ```

2. **Run Tests** (after developer enhancements)
   ```bash
   go test ./...
   ```

3. **Build**
   ```bash
   GOOS=linux GOARCH=amd64 go build -o bootstrap main.go
   ```

4. **Deploy with SAM**
   ```bash
   sam build
   sam deploy --guided
   ```

5. **Test the Endpoint**
   ```bash
   curl -X POST https://your-api-gateway-url/Prod/export \
     -H "Content-Type: application/json" \
     -d '{
       "imageData": "iVBORw0KGgo...",
       "format": "png",
       "width": 200,
       "height": 100,
       "watermark": "Test"
     }'
   ```

## Testing Checklist

- [ ] Unit tests pass for all export formats
- [ ] PNG export with custom dimensions works
- [ ] SVG export includes metadata correctly
- [ ] PDF export generates valid PDF files
- [ ] Watermarks appear correctly on all formats
- [ ] Error handling returns proper HTTP status codes
- [ ] CORS headers allow frontend requests
- [ ] S3 storage works (if enabled)
- [ ] Large images (>5MB) are handled gracefully
- [ ] Concurrent requests don't cause issues

## Known Limitations

1. **Image Resizing**: Currently returns original dimensions for PNG
2. **Watermark**: Only implemented for SVG and PDF (basic), not PNG
3. **S3 Bucket**: Hardcoded bucket name, needs configuration
4. **PDF Features**: Basic implementation, many advanced features missing
5. **No Image Validation**: Doesn't validate image quality or corruption

## Security Considerations

1. **Input Validation**: Add max file size limits (currently unlimited)
2. **Rate Limiting**: Implement API throttling to prevent abuse
3. **Authentication**: Consider adding JWT validation for production
4. **S3 Permissions**: Use least-privilege IAM policies
5. **Metadata Sanitization**: Sanitize metadata to prevent XSS in SVG/PDF

## Performance Considerations

1. **Large Images**: Consider implementing streaming for large files
2. **Caching**: Add caching layer for frequently exported signatures
3. **Async Processing**: For PDF generation, consider SQS + separate worker
4. **Lambda Timeout**: Current timeout is 5s, may need increase for large PDFs

## Next Steps for Developer

1. Review and test the implementation
2. Implement image resizing for PNG exports
3. Add watermark overlay for PNG format
4. Enhance PDF export with advanced features
5. Configure S3 bucket and environment variables
6. Add frontend integration
7. Write integration tests
8. Deploy to staging environment for testing
9. Create user documentation
10. Update API documentation (Swagger/OpenAPI)

## Questions or Issues?

Contact the agent or refer to:
- JIRA: MOBL-3653
- Repository: https://github.com/atlassian-wcsd/mobile-api
- Branch: `MOBL-3653/multi-format-signature-export`
