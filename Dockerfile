FROM golang:1.15 AS build-server
WORKDIR /app
COPY . .
RUN make server

# FROM google/dart:2.10 AS build-admin
# WORKDIR /app
# COPY admin .
# RUN make admin

FROM alpine:latest
COPY --from=build-server /app/bin/ftauth /usr/local/bin/
# COPY --from=build-admin /app/build /etc/ftauth/admin
CMD ["ftauth", "--embedded"]