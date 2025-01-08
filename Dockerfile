FROM golang:1.23-alpine AS build_deps

RUN apk add --no-cache git

WORKDIR /workspace

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o cloud-dns-solver -ldflags '-w -extldflags "-static"' .

FROM alpine:3.20

RUN apk add --no-cache ca-certificates libcap

# Create a non-root user and group
RUN addgroup -S solver && adduser -S solver -G solver

COPY --from=build /workspace/cloud-dns-solver /usr/local/bin/cloud-dns-solver
RUN chown solver:solver /usr/local/bin/cloud-dns-solver

# Grant the binary the capability to bind to privileged ports
RUN setcap 'cap_net_bind_service=+ep' /usr/local/bin/cloud-dns-solver

USER solver

ENTRYPOINT ["cloud-dns-solver"]
