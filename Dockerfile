FROM --platform=amd64 golang:1.17 AS build-server
WORKDIR /app

COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download

COPY . .
ARG TARGETPLATFORM
RUN export GOARCH=$(echo $TARGETPLATFORM | cut -d / -f 2) && \
    make server

FROM debian:latest
COPY --from=build-server /app/bin/ftauth /usr/local/bin/

EXPOSE 8000
ENTRYPOINT [ "ftauth" ]
CMD [ "--embedded" ]