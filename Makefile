build:
	go build -o thanos-promql-connector

docker:
	docker build --platform linux/amd64 . -t sepa/thanos-promql-connector
