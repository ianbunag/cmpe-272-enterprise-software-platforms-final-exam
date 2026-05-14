FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod .
COPY cmd/sender/ cmd/sender/
RUN CGO_ENABLED=0 go build -o sender ./cmd/sender/

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /build/sender .
CMD ["sleep", "infinity"]
