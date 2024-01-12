FROM golang:1.16.3-alpine3.13 as builder
WORKDIR /app
COPY beats.go .
RUN go build beats.go
CMD ["./beats"]
