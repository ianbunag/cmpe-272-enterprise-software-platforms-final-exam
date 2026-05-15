FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod .
COPY cmd/sender/ cmd/sender/
RUN CGO_ENABLED=0 go build -o /sender ./cmd/sender

FROM alpine:3.19
COPY --from=builder /sender /sender
CMD ["sleep", "infinity"]
