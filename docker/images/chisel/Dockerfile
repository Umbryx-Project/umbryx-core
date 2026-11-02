# chisel — TCP tunnel (reverse NAT traversal for C2/pivot links).
FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git && git clone --depth 1 https://github.com/jpillora/chisel /src
WORKDIR /src
RUN go build -ldflags='-s -w' -o /out/chisel .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /out/chisel /usr/local/bin/chisel
ENTRYPOINT ["chisel"]
