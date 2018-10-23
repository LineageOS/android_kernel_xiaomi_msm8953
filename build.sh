#!/bin/sh


KERNEL_NAME="SkyArk-1.7"
DEVICE="mido"
export KBUILD_BUILD_USER=reza-adi-pangestu
export KBUILD_BUILD_HOST=axioo
export ARCH=arm64
export SUBARCH=arm64


export CLANG_PATH=/home/reza/clang-8.0.2/bin
export PATH=${CLANG_PATH}:${PATH}
export CLANG_TRIPLE=aarch64-linux-gnu-

export CROSS_COMPILE=/home/reza/skyark/aarch64-linux-android-4.9/bin/aarch64-linux-android-

export CLANG_TCHAIN="/home/reza/clang-8.0.2/bin/clang"
export KBUILD_COMPILER_STRING="$(${CLANG_TCHAIN} --version | head -n 1 | perl -pe 's/\(http.*?\)//gs' | sed -e 's/  */ /g')"


make clean O=out/
make mrproper O=out/


make mido_defconfig O=out/

make -j8 O=out/

