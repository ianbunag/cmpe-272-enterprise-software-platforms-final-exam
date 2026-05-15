FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go.mod .
COPY cmd/receiver/ cmd/receiver/
RUN CGO_ENABLED=0 go build -o /receiver ./cmd/receiver

FROM alpine:3.19
COPY --from=builder /receiver /receiver
CMD ["sleep", "infinity"]
