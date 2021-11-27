FROM --platform=amd64 dart:2.14 AS build-frontend

COPY web /web
WORKDIR /web

RUN dart pub get
RUN dart compile js web/main.dart -m -o main.js

FROM --platform=$BUILDPLATFORM golang:1.17 AS build-server
WORKDIR /app

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .
COPY --from=build-frontend /web/main.js /app/cmd/server/static/js/main.js
ARG TARGETPLATFORM
RUN export GOARCH=$(echo $TARGETPLATFORM | cut -d / -f 2) && \
    make server

FROM debian:latest
COPY --from=build-server /app/bin/ftauth /usr/local/bin/

EXPOSE 8000
ENTRYPOINT [ "ftauth" ]
CMD [ "--embedded" ]