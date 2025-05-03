build: 
	@go build -o ./bin/backend-hub

run: build
	@./bin/backend-hub