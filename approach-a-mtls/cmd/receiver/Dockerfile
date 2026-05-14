FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod .
COPY cmd/receiver/ cmd/receiver/
RUN CGO_ENABLED=0 go build -o receiver ./cmd/receiver/

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /build/receiver .
CMD ["sleep", "infinity"]
