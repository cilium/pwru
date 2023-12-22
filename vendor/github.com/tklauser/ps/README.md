# ps

[![Go Reference](https://pkg.go.dev/badge/github.com/tklauser/ps.svg)][1]
[![GitHub Action Status](https://github.com/tklauser/ps/workflows/Tests/badge.svg)](https://github.com/tklauser/ps/actions?query=workflow%3ATests)

Package `ps` provides functionality to find, list and inspect operating system
processes, without using cgo or external binaries.

Supported operating systems: Linux, macOS, FreeBSD, NetBSD, OpenBSD,
DragonflyBSD, Solaris/Illumos, Windows

Not all process information may be supported on all platforms. See the
[Go package reference][1] for details.

This package is inspired by the [github.com/mitchellh/go-ps][2] and
[github.com/keybase/go-ps][3] packages (the latter being a fork of the former).
However, this package supports more operating systems, provides extended
process information and uses only functionality from the Go standard libary and
the [golang.org/x/sys/unix][4] and [golang.org/x/sys/windows][5] packages to
retrieve information from the operating system, i.e. without using cgo or
shelling out to external programs.

[1]: https://pkg.go.dev/github.com/tklauser/ps
[2]: https://github.com/mitchellh/go-ps
[3]: https://github.com/keybase/go-ps
[4]: https://pkg.go.dev/golang.org/x/sys/unix
[5]: https://pkg.go.dev/golang.org/x/sys/windows
