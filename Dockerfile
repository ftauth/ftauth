FROM golang:1.15-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o server cmd/main.go

FROM alpine:latest
COPY --from=build /app/server /usr/local/bin/
CMD ["server"]