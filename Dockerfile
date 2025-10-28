# Builder stage
FROM rust:1.90.0 AS builder

WORKDIR /app
RUN apt update && apt install -y lld clang
COPY . .
COPY .sqlx .sqlx
ENV SQLX_OFFLINE=true
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim AS runtime

WORKDIR /app

# Install necessary runtime dependencies
RUN apt-get update -y \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && apt-get autoremove -y \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary and configs
COPY --from=builder /app/target/release/onetimesecret_rs ./onetimesecret_rs
COPY configuration configuration

ENV APP_ENVIRONMENT=production

EXPOSE 8000

ENTRYPOINT ["./onetimesecret_rs"]