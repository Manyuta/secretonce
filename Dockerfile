# Chef stage for dependency analysis
FROM lukemathwalker/cargo-chef:latest-rust-1.90.0 AS chef
WORKDIR /app
RUN apt update && apt install -y lld clang

# Planner stage - analyzes dependencies
FROM chef AS planner
COPY . .
# Compute a lock-like file for dependency installation
RUN cargo chef prepare --recipe-path recipe.json

# Builder stage - caches dependencies
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Build dependencies - this layer is cached as long as Cargo.toml/Cargo.lock don't change
RUN cargo chef cook --release --recipe-path recipe.json

# Build the application
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
COPY --from=builder /app/target/release/secretonce ./secretonce
COPY configuration configuration

ENV APP_ENVIRONMENT=production

EXPOSE 8000

ENTRYPOINT ["./secretonce"]