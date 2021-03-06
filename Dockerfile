FROM --platform=$BUILDPLATFORM golang:1.16 AS build-server
WORKDIR /app
COPY . .
ARG TARGETPLATFORM
RUN export GOARCH=$(echo $TARGETPLATFORM | cut -d / -f 2) && \
    make server

# FROM google/dart:2.10 AS build-admin
# WORKDIR /app
# COPY admin .
# RUN make admin

FROM alpine:latest
COPY --from=build-server /app/bin/ftauth /usr/local/bin/
# COPY --from=build-admin /app/build /etc/ftauth/admin

EXPOSE 8000
CMD ["ftauth", "--embedded"]