FROM golang:1.23-alpine AS build_deps

RUN apk add --no-cache git

WORKDIR /workspace

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o cloud-dns-solver -ldflags '-w -extldflags "-static"' .

FROM alpine:3.18

RUN apk add --no-cache ca-certificates

COPY --from=build /workspace/cloud-dns-solver /usr/local/bin/cloud-dns-solver

ENTRYPOINT ["cloud-dns-solver"]
