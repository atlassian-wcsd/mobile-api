package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"submitFeedback/opendevopslambda"
)

func main() {
	sess := session.Must(session.NewSession())
	d := opendevopslambda.Dependency{
		DepDynamoDB: dynamodb.New(sess),
	}
	lambda.Start(d.Handler)
}
