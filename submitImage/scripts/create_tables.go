package main

import (
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
)

func main() {
	// Create AWS session
	sess := session.Must(session.NewSession())
	svc := dynamodb.New(sess)

	// Create Users table
	err := createUsersTable(svc)
	if err != nil {
		log.Printf("Error creating Users table: %v", err)
		os.Exit(1)
	}

	log.Println("Successfully created Users table")
}

func createUsersTable(svc *dynamodb.DynamoDB) error {
	tableName := "Users"

	// Check if table already exists
	_, err := svc.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err == nil {
		log.Printf("Table %s already exists", tableName)
		return nil
	}

	// Create table
	input := &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []*dynamodb.AttributeDefinition{
			{
				AttributeName: aws.String("id"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("username"),
				AttributeType: aws.String("S"),
			},
			{
				AttributeName: aws.String("email"),
				AttributeType: aws.String("S"),
			},
		},
		KeySchema: []*dynamodb.KeySchemaElement{
			{
				AttributeName: aws.String("id"),
				KeyType:       aws.String("HASH"),
			},
		},
		GlobalSecondaryIndexes: []*dynamodb.GlobalSecondaryIndex{
			{
				IndexName: aws.String("username-index"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("username"),
						KeyType:       aws.String("HASH"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
			{
				IndexName: aws.String("email-index"),
				KeySchema: []*dynamodb.KeySchemaElement{
					{
						AttributeName: aws.String("email"),
						KeyType:       aws.String("HASH"),
					},
				},
				Projection: &dynamodb.Projection{
					ProjectionType: aws.String("ALL"),
				},
				ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
		},
		ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	}

	_, err = svc.CreateTable(input)
	if err != nil {
		return fmt.Errorf("failed to create table: %w", err)
	}

	// Wait for table to be created
	log.Printf("Waiting for table %s to be created...", tableName)
	err = svc.WaitUntilTableExists(&dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err != nil {
		return fmt.Errorf("failed to wait for table creation: %w", err)
	}

	return nil
}