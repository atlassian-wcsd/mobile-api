module healthcheck

go 1.21

replace submit-image => ../submitImage

require (
	github.com/aws/aws-lambda-go v1.41.0
	github.com/aws/aws-sdk-go v1.44.290
	submit-image v0.0.0-00010101000000-000000000000
)

require (
	github.com/google/uuid v1.2.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
)
