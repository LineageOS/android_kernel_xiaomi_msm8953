#!/bin/sh
# Copyright (C) 2018 Adesh Ikhar (Adesh15)

#TG send message function
if [ "$CHAT" == "group" ]
then
export CHAT_ID="-1001163172007 $CHAT_ID";
fi
if [ "$CHAT" == "adesh" ]
then
export CHAT_ID="-318772221 $CHAT_ID";
fi

function sendTG()
{
for f in $CHAT_ID
do
bash ~/reactor/send_tg.sh $f $@
done
}

NC='\033[0m'
RED='\033[0;31m'
LGR='\033[1;32m'

ROOT_PATH=$PWD

export KBUILD_BUILD_USER=adesh15
export KBUILD_BUILD_HOST=reactor
export ARCH=arm64
export SUBARCH=arm64
export IMAGE="${ROOT_PATH}/out/arch/${ARCH}/boot/Image.gz-dtb";
export ZIPDIR="/home/adesikha15/zip";

clean()
{
echo -e ${LGR} "############### Cleaning Up ################${NC}"
rm -rf $ZIPDIR/*.zip
rm -rf $ZIPDIR/Image*
}

status()
{
if [ ! -f "${IMAGE}" ]; then
echo -e ${RED} "#################################################"
echo -e ${RED} "# Build failed, check warnings/errors! #"
echo -e ${RED} "#################################################${NC}"
sendTG "KERNEL BUILD FAILED, RIP in pieces.";
sendTG "@Adesh15, check console fast.";
exit 1;
else
echo -e ${LGR} "#################################################"
echo -e ${LGR} "############### Build competed! #################"
echo -e ${LGR} "#################################################${NC}"
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
export FINAL_ZIP="${ZIPDIR}/Feather-mido-clang-$(date +"%Y%m%d")-$(date +"%H%M%S").zip"
else
export TOOLCHAIN=/home/adesikha15/toolchain/bin/aarch64-linux-
export CROSS_COMPILE="${CCACHE} ${TOOLCHAIN}"
export FINAL_ZIP="${ZIPDIR}/Feather-mido-$(date +"%Y%m%d")-$(date +"%H%M%S").zip"
fi
make clean O=out/
make mrproper O=out/
echo -e ${LGR} "############# Generating Defconfig ##############${NC}"
if [ "$CLANG" == "yes" ]
then
make CC=clang mido_defconfig O=out/
else
make mido_defconfig O=out/
fi
}

compile()
{
echo -e ${LGR} "############### Compiling kernel ################${NC}"
if [ "$CLANG" == "yes" ]
then
sendTG "Starting $(date +%Y%m%d) Feather Clang [build]($BUILD_URL)."
make CC=clang -j$(nproc --all) O=out/
else
sendTG "Starting $(date +%Y%m%d) Feather [build]($BUILD_URL)."
make -j$(nproc --all) O=out/
fi
status
}

zipit()
{
echo "Copying kernel image";
cd "${ZIPDIR}"
cp -v "${IMAGE}" "${ZIPDIR}";
cd "${ZIPDIR}"
zip -r9 "${FINAL_ZIP}" *;
size=$(du -sh $FINAL_ZIP | awk '{print $1}')
fileid=$(~/gdrive upload --parent 1WUgQdNirCz7u7FjXZNgstbCgDrjD4OUg ${FINAL_ZIP} | tail -1 | awk '{print $2}')
sendTG "[Google Drive](https://drive.google.com/uc?id=$fileid&export=download)"
sendTG "FileSize - $size"
sendTG "Kernal lelo frandz";
sendTG "${POST_MESSAGE}";
}

START=$(date +"%s")
clean
defconfig
compile
zipit
END=$(date +"%s")
DIFF=$((END - START))
echo "Build took $((DIFF / 60)) minute(s) and $((DIFF % 60)) seconds.";

cd $ROOT_PATH
