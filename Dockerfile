# Build stage
FROM rust:bookworm AS builder

WORKDIR /usr/src/rproxy
COPY . .

# Build the release binary. We build dynamically with glibc because monoio/io_uring 
# relies on certain Linux syscalls (like statx) that are incomplete in musl libc.
RUN cargo build --release

# Final minimal stage
FROM scratch

# Copy glibc and necessary runtime libraries from builder
COPY --from=builder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/
COPY --from=builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/
COPY --from=builder /lib64/ld-linux-x86-64.so.2 /lib64/

# Copy the CA certificates to support TLS upstream connections
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the dynamically compiled binary
COPY --from=builder /usr/src/rproxy/target/release/rproxy /rproxy

WORKDIR /
EXPOSE 8080

ENTRYPOINT ["/rproxy"]
