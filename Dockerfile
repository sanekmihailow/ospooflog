FROM golang:1.23-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY pkg ./pkg

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /out/ospooflog \
    ./cmd/ospooflog

FROM scratch
COPY --from=build /out/ospooflog /usr/local/bin/ospooflog
ENTRYPOINT ["/usr/local/bin/ospooflog"]
