package opendevopslambda

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockedS3 struct {
	s3iface.S3API
	putObjectFn    func(*s3.PutObjectInput) (*s3.PutObjectOutput, error)
	deleteObjectFn func(*s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error)
}

func (m mockedS3) PutObject(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
	if m.putObjectFn != nil {
		return m.putObjectFn(input)
	}
	return &s3.PutObjectOutput{}, nil
}

func (m mockedS3) DeleteObject(input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
	if m.deleteObjectFn != nil {
		return m.deleteObjectFn(input)
	}
	return &s3.DeleteObjectOutput{}, nil
}

type mockedDynamoDB struct {
	dynamodbiface.DynamoDBAPI
	getItemFn func(*dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error)
	putItemFn func(*dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error)
}

func (m mockedDynamoDB) GetItem(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
	if m.getItemFn != nil {
		return m.getItemFn(input)
	}
	return &dynamodb.GetItemOutput{}, nil
}

func (m mockedDynamoDB) PutItem(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
	if m.putItemFn != nil {
		return m.putItemFn(input)
	}
	return &dynamodb.PutItemOutput{}, nil
}

func lambdaTestContext() context.Context {
	ctx := context.Background()
	lc := &lambdacontext.LambdaContext{
		InvokedFunctionArn: "arn:aws:lambda:us-east-1:123456789000:function:functionName",
	}
	return lambdacontext.NewContext(ctx, lc)
}

func TestHandlerReturnsSignatureReceipt(t *testing.T) {
	defer func(originalNowFunc func() time.Time) { nowFunc = originalNowFunc }(nowFunc)
	nowFunc = func() time.Time {
		return time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	}

	var storedImageBytes []byte
	var persistedImageHash string

	d := Dependency{
		DepS3: mockedS3{
			putObjectFn: func(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
				readBody, err := io.ReadAll(input.Body)
				require.NoError(t, err)
				storedImageBytes = readBody
				return &s3.PutObjectOutput{}, nil
			},
		},
		DepDynamoDB: mockedDynamoDB{
			getItemFn: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{}, nil
			},
			putItemFn: func(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
				require.NotNil(t, input.Item["ImageHash"])
				require.NotNil(t, input.Item["ImageHash"].S)
				persistedImageHash = *input.Item["ImageHash"].S
				return &dynamodb.PutItemOutput{}, nil
			},
		},
	}

	request := events.APIGatewayProxyRequest{
		Body: `{"imageData":"data:image/png;base64,` + base64.StdEncoding.EncodeToString([]byte("signed-image")) + `"}`,
	}

	response, err := d.Handler(lambdaTestContext(), request)
	require.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)

	var receipt signatureReceipt
	require.NoError(t, json.Unmarshal([]byte(response.Body), &receipt))

	expectedHashBytes := sha256.Sum256([]byte("signed-image"))
	expectedHash := hex.EncodeToString(expectedHashBytes[:])
	assert.Equal(t, expectedHash, receipt.ImageHash)
	assert.Equal(t, expectedHash, persistedImageHash)
	assert.Equal(t, "sig_"+expectedHash, receipt.SignatureID)
	assert.Equal(t, "signatures/sig_"+expectedHash, receipt.S3Key)
	assert.Equal(t, "2026-07-06T12:00:00Z", receipt.SubmittedAt)
	assert.Equal(t, []byte("signed-image"), storedImageBytes)
}

func TestHandlerDynamoFailureTriggersS3Rollback(t *testing.T) {
	rolledBack := false

	d := Dependency{
		DepS3: mockedS3{
			putObjectFn: func(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
				return &s3.PutObjectOutput{}, nil
			},
			deleteObjectFn: func(input *s3.DeleteObjectInput) (*s3.DeleteObjectOutput, error) {
				rolledBack = true
				return &s3.DeleteObjectOutput{}, nil
			},
		},
		DepDynamoDB: mockedDynamoDB{
			getItemFn: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{}, nil
			},
			putItemFn: func(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
				return nil, errors.New("dynamodb put failed")
			},
		},
	}

	request := events.APIGatewayProxyRequest{
		Body: `{"imageData":"` + base64.StdEncoding.EncodeToString([]byte("rollback-image")) + `"}`,
	}

	response, err := d.Handler(lambdaTestContext(), request)
	require.Error(t, err)
	assert.Equal(t, 500, response.StatusCode)
	assert.True(t, rolledBack)
}

func TestHandlerReturnsExistingReceiptForIdempotentResubmission(t *testing.T) {
	existing := signatureReceipt{
		SignatureID: "sig_hash",
		S3Key:       "signatures/sig_hash",
		SubmittedAt: "2026-07-06T12:00:00Z",
		ImageHash:   "hash",
	}

	s3Called := false
	putItemCalled := false

	d := Dependency{
		DepS3: mockedS3{
			putObjectFn: func(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
				s3Called = true
				return &s3.PutObjectOutput{}, nil
			},
		},
		DepDynamoDB: mockedDynamoDB{
			getItemFn: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{
					Item: map[string]*dynamodb.AttributeValue{
						"Id":          {S: aws.String(existing.SignatureID)},
						"S3Key":       {S: aws.String(existing.S3Key)},
						"SubmittedAt": {S: aws.String(existing.SubmittedAt)},
						"ImageHash":   {S: aws.String(existing.ImageHash)},
					},
				}, nil
			},
			putItemFn: func(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
				putItemCalled = true
				return &dynamodb.PutItemOutput{}, nil
			},
		},
	}

	request := events.APIGatewayProxyRequest{
		Body: `{"imageData":"` + base64.StdEncoding.EncodeToString([]byte("image")) + `"}`,
	}

	response, err := d.Handler(lambdaTestContext(), request)
	require.NoError(t, err)
	assert.Equal(t, 200, response.StatusCode)
	assert.False(t, s3Called)
	assert.False(t, putItemCalled)

	var receipt signatureReceipt
	require.NoError(t, json.Unmarshal([]byte(response.Body), &receipt))
	assert.Equal(t, existing, receipt)
}

func TestProcessRequestHandlesConditionalWriteAsIdempotent(t *testing.T) {
	alreadyStored := signatureReceipt{
		SignatureID: "sig_hash",
		S3Key:       "signatures/sig_hash",
		SubmittedAt: "2026-07-06T12:00:00Z",
		ImageHash:   "hash",
	}

	getItemCount := 0
	d := Dependency{
		DepS3: mockedS3{
			putObjectFn: func(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
				return &s3.PutObjectOutput{}, nil
			},
		},
		DepDynamoDB: mockedDynamoDB{
			getItemFn: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				getItemCount++
				if getItemCount == 1 {
					return &dynamodb.GetItemOutput{}, nil
				}
				return &dynamodb.GetItemOutput{
					Item: map[string]*dynamodb.AttributeValue{
						"Id":          {S: aws.String(alreadyStored.SignatureID)},
						"S3Key":       {S: aws.String(alreadyStored.S3Key)},
						"SubmittedAt": {S: aws.String(alreadyStored.SubmittedAt)},
						"ImageHash":   {S: aws.String(alreadyStored.ImageHash)},
					},
				}, nil
			},
			putItemFn: func(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
				return nil, awserr.New(dynamodb.ErrCodeConditionalCheckFailedException, "exists", nil)
			},
		},
	}

	receipt, err := d.processRequest([]byte("conditional"), "us-east-1", "123456789000")
	require.NoError(t, err)
	assert.Equal(t, alreadyStored, receipt)
}

func TestDecodeImageDataReturnsRawDecodedBytes(t *testing.T) {
	imageData := base64.StdEncoding.EncodeToString([]byte("hash-me"))
	decoded, err := decodeImageData(imageData)
	require.NoError(t, err)
	assert.Equal(t, []byte("hash-me"), decoded)

	dataUrl := "data:image/png;base64," + imageData
	decodedFromDataURL, err := decodeImageData(dataUrl)
	require.NoError(t, err)
	assert.Equal(t, []byte("hash-me"), decodedFromDataURL)
}

func TestProcessRequestHashMatchesStoredS3Bytes(t *testing.T) {
	var s3Bytes []byte
	var persistedHash string

	d := Dependency{
		DepS3: mockedS3{
			putObjectFn: func(input *s3.PutObjectInput) (*s3.PutObjectOutput, error) {
				content, err := io.ReadAll(input.Body)
				require.NoError(t, err)
				s3Bytes = bytes.Clone(content)
				return &s3.PutObjectOutput{}, nil
			},
		},
		DepDynamoDB: mockedDynamoDB{
			getItemFn: func(input *dynamodb.GetItemInput) (*dynamodb.GetItemOutput, error) {
				return &dynamodb.GetItemOutput{}, nil
			},
			putItemFn: func(input *dynamodb.PutItemInput) (*dynamodb.PutItemOutput, error) {
				require.NotNil(t, input.Item["ImageHash"])
				require.NotNil(t, input.Item["ImageHash"].S)
				persistedHash = *input.Item["ImageHash"].S
				return &dynamodb.PutItemOutput{}, nil
			},
		},
	}

	payload := []byte("exact-bytes")
	receipt, err := d.processRequest(payload, "us-east-1", "123456789000")
	require.NoError(t, err)

	hashOfS3Bytes := sha256.Sum256(s3Bytes)
	expectedHash := hex.EncodeToString(hashOfS3Bytes[:])
	assert.Equal(t, expectedHash, receipt.ImageHash)
	assert.Equal(t, expectedHash, persistedHash)
}
