# Build either image from the workspace root:
#   docker build --build-arg BIN=secrets-demo-api -t secrets-demo-api .
#   docker build --build-arg BIN=secrets-demo-web -t secrets-demo-web .
FROM rust:1-bookworm AS build
ARG BIN
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY api api
COPY web web
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p ${BIN} && cp target/release/${BIN} /app

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /app /app
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app"]
