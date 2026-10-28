# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/header-grader ./cmd/header-grader

FROM alpine:3.21
# ca-certificates is required: without it every HTTPS scan fails verification
# and would be graded as if the site were broken.
RUN apk add --no-cache ca-certificates \
 && adduser -D -u 10001 grader
COPY --from=build /out/header-grader /usr/local/bin/header-grader
USER grader
ENTRYPOINT ["/usr/local/bin/header-grader"]
