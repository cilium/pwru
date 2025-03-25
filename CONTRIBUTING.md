# Contributing

`pwru` is an open source project. The userspace code is licensed under [Apache-2.0](LICENSE), while the BPF under [BSD 2-Clause](bpf/LICENSE.BSD-2-Clause) and [GPL-2.0](bpf/LICENSE.GPL-2.0). Everybody is welcome to contribute. Contributors are required to follow the [CNCF Code of
Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md) and must adhere to the [Developer Certificate of Origin](https://developercertificate.org/) by adding a Signed-off-by line to their commit messages.

## Getting Started

- Read the [README](https://github.com/cilium/pwru#readme) to understand how `pwru` works and its use cases.
- Check out the [issues list](https://github.com/cilium/pwru/issues) for open tasks, especially those labeled `good first issue`.

## Developing  

If you're looking to contribute code to `pwru`, you'll need to set up your development environment with the required dependencies and build the project locally.  

### Dependencies  

Ensure you have the following installed:  

- Go >= 1.16  
- LLVM/Clang >= 12  
- Bison  
- Lex/Flex >= 2.5.31  

### Building  

To build `pwru`, simply run:  

```
make
```

Alternatively, you can build it within a Docker container:

```
make release
```

## Contributor Ladder  

Cilium has a well-defined [contributor ladder](https://github.com/cilium/community/blob/main/CONTRIBUTOR-LADDER.md) to help community members grow both responsibilities and privileges in the ecosystem. This ladder outlines the path from an occasional contributor to a committer, detailing expectations at each stage. Most contributors start at the community level and progress as they become more engaged in the project. We encourage you to take an active role, and the community is here to support you on this journey.  

Becoming a [Cilium organization member](https://github.com/cilium/community/blob/main/CONTRIBUTOR-LADDER.md#organization-member) grants you additional privileges, such as the ability to trigger CI runs. If you're contributing regularly to `pwru`, consider joining the [pwru team](https://github.com/cilium/community/blob/main/ladder/teams/pwru.yaml) to help review code and accelerate development. Your contributions play a vital role in improving the project, and we'd love to have you more involved!

## Community

Join the Cilium community for discussions:

Slack: [Cilium Slack](https://slack.cilium.io/) in #pwru
GitHub Discussions: [cilium/pwru discussions](https://github.com/cilium/pwru/discussions)

We appreciate your contributions to `pwru` and look forward to your involvement!
