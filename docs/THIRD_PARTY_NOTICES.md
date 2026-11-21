# Third-party notices

## Capstone

The native NSO rewriter uses the Capstone disassembly engine through
[libcapstone-spm](https://github.com/Lakr233/libcapstone-spm), which vendors
Capstone and provides a Swift Package Manager wrapper.

- Upstream project: https://github.com/capstone-engine/capstone
- Wrapper package: https://github.com/Lakr233/libcapstone-spm
- Version pin: 0.1.3
- License: BSD 3-Clause

The BSD 3-Clause license requires retaining the copyright notice, conditions,
and disclaimer in source redistributions, and reproducing them in documentation
or other materials for binary redistributions. The upstream license text is
available in the wrapper package's `LICENSE` file and must accompany any
distributed Box3 binary containing Capstone.

Capstone is used only as an in-process AArch64 instruction decoder. Game dumps,
production keys, and conversion inputs are not sent to the package maintainer
or to a remote service.
