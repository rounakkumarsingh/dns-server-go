# Build stage
FROM golang:latest AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o dns-server .

# Run stage
FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/dns-server .

EXPOSE 53/udp

ENTRYPOINT ["./dns-server"]
