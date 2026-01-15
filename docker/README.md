# phantun (docker)

## Build

```sh
docker build -t phantun -f docker/Dockerfile .
```

## Cross-compile release artifacts (no local Rust needed)

This produces the requested multi-CPU release archives:

- `phantun_armv7-unknown-linux-gnueabihf.tar.gz`
- `phantun_x64_musl.tar.gz`

```sh
docker buildx build \
  --output type=local,dest=dist \
  -f docker/Dockerfile.build \
  .
```

Artifacts will be written to `dist/`. Each archive contains `phantun-server` and
`phantun-client` for that target.

## Usage

It is recommended to use docker-compose, see [docker-compose.yml](docker-compose.yml) for details.
