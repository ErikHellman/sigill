# Static (musl) build of the sigill binary and a small runtime image.
FROM rust:1.100-alpine AS build
RUN apk add --no-cache musl-dev gcc
WORKDIR /src
COPY . .
ENV SQLX_OFFLINE=true
RUN cargo build --release --locked -p sigill --target x86_64-unknown-linux-musl \
 && cp target/x86_64-unknown-linux-musl/release/sigill /sigill

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S sigill && adduser -S -G sigill -h /var/lib/sigill sigill
COPY --from=build /sigill /usr/local/bin/sigill
USER sigill
WORKDIR /var/lib/sigill
ENTRYPOINT ["/usr/local/bin/sigill"]
CMD ["--config", "/etc/sigill/sigill.toml", "serve"]
