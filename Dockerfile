FROM golang:1.25-alpine AS build
WORKDIR /app
RUN apk add --no-cache build-base
COPY go.mod go.sum ./
COPY main.go ./
RUN go build -o mailpit2slack

FROM alpine:3.22
WORKDIR /app
COPY --from=build /app/mailpit2slack /app/mailpit2slack

ENV POLL_INTERVAL_SECONDS=10
ENTRYPOINT ["/app/mailpit2slack"]
