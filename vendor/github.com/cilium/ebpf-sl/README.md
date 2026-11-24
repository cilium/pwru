# ebpf-go signable loader

In Linux kernel v6.18, eBPF program signing was [introduced](https://lore.kernel.org/all/20250921160120.9711-1-kpsingh@kernel.org/). Due to the technical requirements of program signing, a significant amount of work has to be reimplemented from our base cilium/ebpf repo.

This repository contains:
* A signable loader code generation library (root package)
* A load time library (`signable` package)
* A command line utility for the code generation library (`cmd/bpf2sl`)

## Usage

There are several ways to use the tools and libraries. Going from a ELF file to having loaded the programs is a multi-step process, some of which be done ahead of time or at load time.

### Build time codegen and signing

This is the most secure way. We take a ELF file and generate a signable loader from it, the output of which is a Golang file containing the signable loader, the contents of the ELF file in a custom format, and the signature.

```
go run github.com/cilium/ebpf-sl/cmd/bpf2sl example.o --cert myx509cert.pem --key myprivate.key
```

The generated Golang file contains global variable of type `signable.Loader`, the `signable.Loader.Load` method is then used at runtime to load the collection, utilizing the embedded signature.

### Build time codegen, load time signing

Similar to the first case we do the generation of the signable loader ahead of time, but we do not provide a certificate or private key.

```
go run github.com/cilium/ebpf-sl/cmd/bpf2sl example.o
```

The generated Golang file contains global variable of type `signable.Loader` but without embedded signature. The `signable.Loader.Sign` method can be used to sign the signable loader at runtime. This is optional, the signable loader can be used without signature, as long as enforcement is disabled.

This method is not recommended because having a private key available to the process increases the possibility of malicious actors stealing it and using it to load malicious programs.

The `signable.Loader.Load` method is then used at runtime to load the collection with or without a signature.

### Load time codegen and signing

The generation step of the signable loader can be invoked at load time by directly calling the library, then signing and loading.

This option allows for easier replacement of [`ebpf.NewCollection`](https://pkg.go.dev/github.com/cilium/ebpf#NewCollection), or for use cases where the target BPF program has to be generated / compiled at load time.

This method is not recommended because having a private key available to the process increases the possibility of malicious actors stealing it and using it to load malicious programs.

## How program signing works

The design of the kernel signing feature has a split the responsibility of verifying signing and enforcement. By default, on a clean system, userspace can load BPF programs without signatures. The owner of a system can chose to install an LSM BPF program to the `bpf_prog_load` hook which has the power to block program loading.

When the `bpf_prog_load` hook has access to a lot of internal information about the program and the conditions under which it is loaded. This includes fields that track if this program has been loaded with a valid signature, if a program is being loaded from userspace or from the kernel (via `BPF_PROG_TYPE_SYSCALL`), and much more. This program would be able to for example block all programs loaded from userspace without valid signature. Crucially, its expected that such an enforcement point would allow `BPF_PROG_TYPE_SYSCALL` programs to load other non-signed BPF programs, as long as the `BPF_PROG_TYPE_SYSCALL` itself was signed. Trust is delegated to a signed loader program. This would allow the trusted loader to make load time modifications for the purposes of relocating inherently dynamic parts such as kfunc relocations.

The task of userspace, this repo, is to take an ELF file, and to generate a static `BPF_PROG_TYPE_SYSCALL` program that invokes all of the system calls `cilium/ebpf` would normally execute from userspace. This is the "signable loader". The signable loader uses a global data map (array map with 1 value) both as data input as well as scratch buffer, this map is referred to as its "metadata". The metadata includes the actual programs from the ELF, partially pre-computed syscall attributes and more. The contents of this map are built at codegen time, its hash calculated and then embedded in the signable loader before signing. The signable loader checks the hash of the metadata during loading to maintain a chain of trust, ensuring the actual programs to be loaded will not have been altered between codegen and actual loading.

During loading, the signature is provided to the kernel as PKCS#7 detached signature, and a keyring ID. The kernel then verifies that the hash of the instruction of the signable loader is the same as the hash that is signed by the signature and that the signature was signed with a certificate that has been loaded into the indicated keyring. The enforcement LSM program also gets to see the keyring used, and may enforce a specific keyring.

Once the signed loader is verified, and accepted by the kernel as signed, we run the signed loader with the `BPF_PROG_RUN` BPF syscall command. Traditionally used for testing programs, but in the case of `BPF_PROG_TYPE_SYSCALL` it executes the BPF program in the context of the calling process. Which means that the BPF program can use open file descriptors of its calling process, and any syscalls it execute add file descriptors to the process directly.
The userspace process can pass arbitrary data to the syscall program via its context. This context is both an input and an output, it can thus be used for load time settings such as verifier log level, log buffer pointer passing and initial values of BPF maps used for global data. The syscall program can write the result of syscalls in there which can be error codes or file descriptors as well as other useful feedback.

## Kernel requirements for BPF program signing

BPF program signing only works on kernel v6.18 and higher and requires the following kconfigs:

* `CONFIG_SYSTEM_DATA_VERIFICATION` - To enable signing support in the kernel
  * This Kconfig is "hidden" and needs to be enabled via another Kconfig. Easiest seems to be to enable `FS_VERITY_BUILTIN_SIGNATURES` and `FS_VERITY`
* `CONFIG_CRYPTO_RSA` - To enable RSA based certificates and signing
* `CONFIG_CRYPTO_ECDSA` - To enable ECDSA (Elliptic Curve) based certificates and signing
* `CONFIG_CRYPTO_MLDSA` - To enable MLDSA (Module-Lattice-based, post-quantum standard) based certificates and signing
* `CONFIG_CRYPTO_SHA256` - To enable SHA-256 signature hashing
* `CONFIG_CRYPTO_SHA512` - To enable SHA-384 and SHA-512 signature hashing
* `CONFIG_CRYPTO_SHA3` - To enable SHA3-256, SHA3-384, and SHA3-512 signature hashing.
