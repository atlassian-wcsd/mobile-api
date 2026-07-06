package opendevopslambda

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambdacontext"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"net/http"
	"strings"
	"time"
)

type Dependency struct {
	DepS3       s3iface.S3API
	DepDynamoDB dynamodbiface.DynamoDBAPI
}

var bucketRootName = "open-devops-images"

var nowFunc = time.Now

type submitImageRequest struct {
	ImageData string `json:"imageData"`
}

type signatureReceipt struct {
	SignatureID string `json:"signatureId"`
	S3Key       string `json:"s3Key"`
	SubmittedAt string `json:"submittedAt"`
	ImageHash   string `json:"imageHash"`
}

func receiptFromDynamoItem(item map[string]*dynamodb.AttributeValue) (signatureReceipt, bool) {
	idAttr, idFound := item["Id"]
	s3KeyAttr, s3KeyFound := item["S3Key"]
	submittedAtAttr, submittedAtFound := item["SubmittedAt"]
	imageHashAttr, imageHashFound := item["ImageHash"]
	if !idFound || !s3KeyFound || !submittedAtFound || !imageHashFound ||
		idAttr == nil || s3KeyAttr == nil || submittedAtAttr == nil || imageHashAttr == nil ||
		idAttr.S == nil || s3KeyAttr.S == nil || submittedAtAttr.S == nil || imageHashAttr.S == nil {
		return signatureReceipt{}, false
	}

	return signatureReceipt{
		SignatureID: *idAttr.S,
		S3Key:       *s3KeyAttr.S,
		SubmittedAt: *submittedAtAttr.S,
		ImageHash:   *imageHashAttr.S,
	}, true
}

func decodeImageData(imageData string) ([]byte, error) {
	if imageData == "" {
		return nil, errors.New("imageData is required")
	}

	base64Part := imageData
	if strings.Contains(imageData, ",") {
		splitImageData := strings.SplitN(imageData, ",", 2)
		base64Part = splitImageData[1]
	}

	decoded, err := base64.StdEncoding.DecodeString(base64Part)
	if err != nil {
		return nil, err
	}

	if len(decoded) == 0 {
		return nil, errors.New("decoded image data is empty")
	}

	return decoded, nil
}

func (d *Dependency) processRequest(imageBytes []byte, region string, awsAccountID string) (signatureReceipt, error) {
	imageHashBytes := sha256.Sum256(imageBytes)
	imageHash := hex.EncodeToString(imageHashBytes[:])
	signatureID := fmt.Sprintf("sig_%s", imageHash)
	s3Key := fmt.Sprintf("signatures/%s", signatureID)
	submittedAt := nowFunc().UTC().Format(time.RFC3339Nano)

	existingItemOutput, getErr := d.DepDynamoDB.GetItem(&dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"Id": {
				S: aws.String(signatureID),
			},
		},
		TableName: aws.String("ImageLabels"),
	})
	if getErr != nil {
		return signatureReceipt{}, getErr
	}

	if existingItemOutput != nil && len(existingItemOutput.Item) > 0 {
		if existingReceipt, ok := receiptFromDynamoItem(existingItemOutput.Item); ok {
			return existingReceipt, nil
		}
	}

	bucketName := fmt.Sprintf("%s-%s-%s", bucketRootName, region, awsAccountID)

	s3Input := &s3.PutObjectInput{
		Body:   bytes.NewReader(imageBytes),
		Bucket: aws.String(bucketName),
		Key:    aws.String(s3Key),
	}

	_, s3err := d.DepS3.PutObject(s3Input)
	if s3err != nil {
		return signatureReceipt{}, s3err
	}

	dynamoInput := &dynamodb.PutItemInput{
		Item: map[string]*dynamodb.AttributeValue{
			"Id": {
				S: aws.String(signatureID),
			},
			"Label": {
				S: aws.String("NOT_CLASSIFIED"),
			},
			"S3Key": {
				S: aws.String(s3Key),
			},
			"SubmittedAt": {
				S: aws.String(submittedAt),
			},
			"ImageHash": {
				S: aws.String(imageHash),
			},
		},
		TableName:           aws.String("ImageLabels"),
		ConditionExpression: aws.String("attribute_not_exists(Id)"),
	}

	_, dynamoErr := d.DepDynamoDB.PutItem(dynamoInput)
	if dynamoErr != nil {
		if awsErr, ok := dynamoErr.(awserr.Error); ok && awsErr.Code() == dynamodb.ErrCodeConditionalCheckFailedException {
			currentItemOutput, currentItemErr := d.DepDynamoDB.GetItem(&dynamodb.GetItemInput{
				Key: map[string]*dynamodb.AttributeValue{
					"Id": {
						S: aws.String(signatureID),
					},
				},
				TableName: aws.String("ImageLabels"),
			})
			if currentItemErr != nil {
				return signatureReceipt{}, currentItemErr
			}

			if currentItemOutput != nil && len(currentItemOutput.Item) > 0 {
				if currentReceipt, ok := receiptFromDynamoItem(currentItemOutput.Item); ok {
					return currentReceipt, nil
				}
			}
		}

		_, rollbackErr := d.DepS3.DeleteObject(&s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(s3Key),
		})
		if rollbackErr != nil {
			return signatureReceipt{}, fmt.Errorf("dynamodb write failed and rollback failed: %w", rollbackErr)
		}

		return signatureReceipt{}, dynamoErr
	}

	return signatureReceipt{
		SignatureID: signatureID,
		S3Key:       s3Key,
		SubmittedAt: submittedAt,
		ImageHash:   imageHash,
	}, nil
}

func (d *Dependency) Handler(ctx context.Context, request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	lc, _ := lambdacontext.FromContext(ctx)
	region := strings.Split(lc.InvokedFunctionArn, ":")[3]
	awsAccountID := strings.Split(lc.InvokedFunctionArn, ":")[4]

	body := request.Body
	if request.IsBase64Encoded {
		decodedBody, decodeErr := base64.StdEncoding.DecodeString(body)
		if decodeErr != nil {
			return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest,
				Body:            `{"error":"invalid request body encoding"}`,
				IsBase64Encoded: false,
			}, decodeErr
		}
		body = string(decodedBody)
	}

	var submitRequest submitImageRequest
	if err := json.Unmarshal([]byte(body), &submitRequest); err != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest,
			Body:            `{"error":"invalid request body"}`,
			IsBase64Encoded: false,
		}, err
	}

	imageBytes, imageErr := decodeImageData(submitRequest.ImageData)
	if imageErr != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusBadRequest,
			Body:            `{"error":"invalid imageData payload"}`,
			IsBase64Encoded: false,
		}, imageErr
	}

	receipt, processErr := d.processRequest(imageBytes, region, awsAccountID)
	if processErr != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError,
			Body:            `{"error":"failed to submit signature"}`,
			IsBase64Encoded: false,
		}, processErr
	}

	receiptBody, marshalErr := json.Marshal(receipt)
	if marshalErr != nil {
		return events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError,
			Body:            `{"error":"failed to build response"}`,
			IsBase64Encoded: false,
		}, marshalErr
	}

	return events.APIGatewayProxyResponse{StatusCode: http.StatusOK,
		Body:            string(receiptBody),
		IsBase64Encoded: false,
	}, nil
}
