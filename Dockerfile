FROM golang:1.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 go build -ldflags "-w -s" -o thanos-promql-connector

FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=builder /app/thanos-promql-connector /thanos-promql-connector
ENTRYPOINT ["/thanos-promql-connector"]
CMD ["--help"]
