#!/bin/sh
# Copyright (C) 2018 Adesh Ikhar (Adesh15)

export TERM=xterm

source ~/reactor/.creds
source ~/scripts/common
source ~/scripts/startupstuff.sh
onLogin

#TG send message function
if [ "$CHAT" == "adesh" ]
then
export CHAT_ID="-318772221 $CHAT_ID"
else
export CHAT_ID="-1001163172007 $CHAT_ID"
fi

ROOT_PATH=$PWD

KERNEL_NAME="Feather"
DEVICE="mido"
export KBUILD_BUILD_USER=adesh15
export KBUILD_BUILD_HOST=reactor
export ARCH=arm64
export SUBARCH=arm64
IMAGE="${ROOT_PATH}/out/arch/${ARCH}/boot/Image.gz-dtb"
ZIPDIR="/home/adesikha15/zip"

clean()
{
echoText "Cleaning Up"
rm -rf $ZIPDIR/*.zip
rm -rf $ZIPDIR/Image*
}

status()
{
if [ ! -f "${IMAGE}" ]; then
reportError "Kernel compilation failed"
sendTG "Build Failed"
sendTG "@Adesh15, check console fast."
exit 1
else
reportSuccess "Build Successful"
sendTG "Build Successful"
fi
}

defconfig()
{
if [ "$CLANG" == "yes" ]
then
export CLANG_PATH=/home/adesikha15/clang/clang-7.0.2/bin
export PATH=${CLANG_PATH}:${PATH}
export CLANG_TRIPLE=aarch64-linux-gnu-
export TCHAIN_PATH="/home/adesikha15/gcc-4.9/bin/aarch64-linux-android-"
export CROSS_COMPILE="${CCACHE} ${TCHAIN_PATH}"
export CLANG_TCHAIN="/home/adesikha15/clang/clang-7.0.2/bin/clang"
export KBUILD_COMPILER_STRING="$(${CLANG_TCHAIN} --version | head -n 1 | perl -pe 's/\(http.*?\)//gs' | sed -e 's/  */ /g')"
FINAL_VER="${KERNEL_NAME}-${DEVICE}-clang"
FINAL_ZIP="${FINAL_VER}-$(date +"%Y%m%d").zip"
else
export TOOLCHAIN=/home/adesikha15/toolchain/bin/aarch64-linux-
export CROSS_COMPILE="${CCACHE} ${TOOLCHAIN}"
FINAL_VER="${KERNEL_NAME}-${DEVICE}"
FINAL_ZIP="${FINAL_VER}-$(date +"%Y%m%d").zip"
fi
make clean O=out/
make mrproper O=out/
echoText "Generating Defconfig"
if [ "$CLANG" == "yes" ]
then
make CC=clang mido_defconfig O=out/
else
make mido_defconfig O=out/
fi
}

compile()
{
echoText "Compiling Kernel"
if [ "$CLANG" == "yes" ]
then
sendTG "Building [${FINAL_VER}]($BUILD_URL)"
make CC=clang -j$(nproc --all) O=out/
else
sendTG "Building [${FINAL_VER}]($BUILD_URL)"
make -j$(nproc --all) O=out/
fi
status
}

zipit()
{
echo "Copying kernel image"
cd "${ZIPDIR}"
cp -v "${IMAGE}" "${ZIPDIR}"
cd "${ZIPDIR}"
zip -r9 "${FINAL_ZIP}" *
size=$(du -sh $FINAL_ZIP | awk '{print $1}')
fileid=$(~/gdrive upload --parent ${KERNEL_BUILDS} ${FINAL_ZIP} | tail -1 | awk '{print $2}')
sendTG "[${FINAL_ZIP}](https://drive.google.com/uc?id=$fileid&export=download)"
sendTG "FileSize - $size"
sendTG "${POST_MESSAGE}"
}

START=$(date +"%s")
clean
defconfig
compile
zipit
END=$(date +"%s")
DIFF=$((END - START))
echoText "Build took $((DIFF / 60)) minute(s) and $((DIFF % 60)) seconds."

cd $ROOT_PATH
