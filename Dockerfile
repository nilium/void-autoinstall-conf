FROM golang:1-alpine AS build

ENV CGO_ENABLED=0
ENV GOBIN=/tmp/bin

WORKDIR /x
COPY . .

RUN go install -v -mod=vendor

FROM alpine:3.9

COPY --from=build /tmp/bin/void-autoinstall-conf /usr/local/bin

EXPOSE 8196
ENTRYPOINT ["/usr/local/bin/void-autoinstall-conf", "-L=0.0.0.0:8196"]
