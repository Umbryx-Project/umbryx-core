FROM alpine:3.19
RUN apk add --no-cache iodine
EXPOSE 53/udp
ENTRYPOINT ["iodined"]
CMD ["-f", "-c", "-P", "changeme", "10.0.0.1", "t.example.com"]
