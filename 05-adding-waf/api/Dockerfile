FROM rust:1.80-alpine AS builder

RUN apk add --no-cache musl-dev postgresql-dev

WORKDIR /usr/src/api

COPY . .

RUN cargo build --release

FROM alpine:3.17

RUN apk add --no-cache libgcc postgresql-libs

COPY --from=builder /usr/src/api/target/release/api /usr/local/bin/api

CMD ["api"]