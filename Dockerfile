FROM golang:1.15 AS build-server
WORKDIR /app
COPY . .
RUN go build -o ftauth cmd/server/main.go

FROM google/dart:2.10 AS build-frontend
WORKDIR /app
COPY admin .

RUN chmod +x script/build.sh
RUN script/build.sh

FROM alpine:latest
COPY --from=build-server /app/ftauth /usr/local/bin/
COPY --from=build-frontend /app/build /etc/ftauth/frontend
CMD ["ftauth"]