.PHONY: build test deploy-dev deploy-prod create-tables clean

build:
	sam build -b build

test:
	cd submitImage && go test ./...

test-coverage:
	cd submitImage && go test -coverprofile=coverage.out ./...
	cd submitImage && go tool cover -html=coverage.out -o coverage.html

create-tables:
	cd submitImage && go run scripts/create_tables.go

deploy-dev:
	sam deploy --config-env dev

deploy-prod:
	sam deploy --config-env prod

clean:
	rm -rf build/
	rm -rf .aws-sam/
	cd submitImage && rm -f coverage.out coverage.html

lint:
	cd submitImage && go vet ./...
	cd submitImage && go fmt ./...

deps:
	cd submitImage && go mod tidy
	cd submitImage && go mod download


