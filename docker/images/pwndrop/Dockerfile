# pwndrop — self-deployable file drop service (github.com/kgretzky/pwndrop).
FROM golang:1.22-alpine AS builder
RUN apk add --no-cache git
RUN git clone --depth 1 https://github.com/kgretzky/pwndrop /src
WORKDIR /src
RUN go build -mod=vendor -ldflags='-s -w' -o /out/pwndrop .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata && mkdir -p /pwndrop/data
COPY --from=builder /out/pwndrop /usr/local/bin/pwndrop
VOLUME /pwndrop/data
EXPOSE 443
WORKDIR /pwndrop/data
ENTRYPOINT ["/usr/local/bin/pwndrop"]
CMD ["run", "-h", "0.0.0.0", "-p", "443", "-d", "/pwndrop/data"]
