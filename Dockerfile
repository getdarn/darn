# Assembled from prebuilt static musl binaries staged into dist/ by
# .github/workflows/release.yml — nothing is compiled here, so buildx puts both
# architectures together in seconds instead of emulating a full OpenSSL build.
#
# Build locally with:
#   cargo build --release --target x86_64-unknown-linux-musl
#   mkdir -p dist/completions && cp target/x86_64-unknown-linux-musl/release/darn dist/darn-amd64
#   ci/gen-dist.sh /usr/bin/darn dist
#   docker build -t darn .
FROM alpine:3.24

ARG TARGETARCH

# openssh-client earns its place: darn rejects unknown host keys, and the
# documented remedy is to ssh to the host once to accept it. Without ssh in the
# image a new host cannot be bootstrapped from inside the container.
# bash is here because the completion script is bash-only — BusyBox ash has no
# `complete` builtin at all, so `docker exec -it <c> bash` is the only way to
# get working tab-completion inside the container.
RUN apk add --no-cache openssh-client bash \
 && adduser -D -h /home/darn darn

COPY dist/darn-${TARGETARCH} /usr/bin/darn
COPY dist/completions/darn.bash /usr/share/bash-completion/completions/darn

USER darn
ENV HOME=/home/darn
WORKDIR /home/darn

ENTRYPOINT ["/usr/bin/darn"]
CMD ["--help"]
