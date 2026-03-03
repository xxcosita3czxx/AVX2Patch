# AVX2Patch

This project is aiming to enable vector instruction sets from SSE4.2 to (hopefully) AVX2 on older Intel CPUs that dont support them natively. Its purpose is to emulate instructions using already available instructions from Penryn architecture and up. This is done by hooking the #UD (Undefined Instruction) exception handler and emulating the missing instructions when they are encountered. Requires opencore [patch](patch.plist) to work.

## Building

To build the project, you will need to have Xcode installed on your Mac. You can then use the following command in the terminal to build the kernel extension:

```bash
make all
```

This will compile the source code and create the `AVX2Patch.kext` file in the `build/Release` directory.

## Docs

This related things to the project:

* [XNU Kernel trap.c](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/i386/trap.c)
* [OpenCore Kernel Patching](https://deepwiki.com/acidanthera/OpenCorePkg/4.2-kernel-patching)

## Thanks

- [@dortania](https://github.com/dortania) for his amazing work on OpenCore wikipedia.
- [@acidanthera](https://github.com/acidanthera) for their contributions to OpenCore and related projects.
- [@apple-oss-distributions](https://github.com/apple-oss-distributions) for their open sourced XNU kernel.
- Everyone who contributed to the development of this project and provided feedback and support.
