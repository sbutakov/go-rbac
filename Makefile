test:
	go test ./... -v -race -count=1 -cover -coverprofile=coverage.txt && go tool cover -func=coverage.txt

lint:
	golangci-lint run --deadline=5m -v
