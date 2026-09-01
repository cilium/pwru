# Packaging pwru for Linux distributions

pwru release binaries are statically linked and have no runtime dependencies beyond a supported kernel. This makes packaging straightforward for major distributions.

## Build a release binary

```shell
make release
```

Artifacts are written to `release/`.

## Debian and Ubuntu (.deb)

Use [nfpm](https://nfpm.goreleaser.com/) with the provided config:

```shell
export VERSION=1.0.0
export ARCH=amd64
nfpm package --config packaging/nfpm.yaml --packager deb
```

## Fedora and RHEL (.rpm)

```shell
export VERSION=1.0.0
export ARCH=amd64
nfpm package --config packaging/nfpm.yaml --packager rpm
```

## Arch Linux

See the [Arch Linux package](https://archlinux.org/packages/extra/x86_64/pwru/) for a maintained source build.

## Notes

- pwru requires Linux kernel >= 5.3 (see README for full kernel config requirements).
- Release binaries are published on each GitHub release. Downstream packages should prefer building from source when packaging guidelines require it.
