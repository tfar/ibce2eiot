#!/usr/bin/env bash

WD_ROOT=$(git rev-parse --show-toplevel)

#export PATH=/Volumes/xtools/arm-none-linux-gnueabi/bin:$PATH
export PATH=/usr/local/linaro/arm-linux-gnueabihf-raspbian/bin:$PATH

rm -rfd build
mkdir build
cd build

echo "Build libcbor"
mkdir libcbor
cd libcbor
cmake -DCMAKE_TOOLCHAIN_FILE=$WD_ROOT/gateway/pi-gcc.cmake -DCMAKE_BUILD_TYPE=Release ../../../3rdParty/libcbor
make -j 7 cbor
cd ..

echo "Build libtins"
mkdir libtins
cd libtins
cmake -DCMAKE_TOOLCHAIN_FILE=$WD_ROOT/gateway/pi-gcc.cmake -DCMAKE_BUILD_TYPE=Release -DLIBTINS_ENABLE_WPA2=0 -DLIBTINS_BUILD_SHARED=0 ../../../3rdParty/libtins
make -j 7 tins
cd ..

echo "Build RELIC"
mkdir relic
cd relic
cmake -DCMAKE_TOOLCHAIN_FILE=$WD_ROOT/gateway/pi-gcc.cmake \
	-DCOMP="-O3 -pthread" \
	-DARCH=NONE \
	-OS=LINUX \
	-DALIGN=1 \
	-DEC_METHD=EDWARD \
	-DFP_PRIME=255 \
	-DED_METHD="PROJC;LWNAF;LWNAF;BASIC" \
	-DSHLIB=off \
	-DBN_PRECI=512 \
	-DWORD=32 \
	-DWITH="ED;EC;MD;FP;BN;DV;CP;BC;EP" \
	-DBN_METHD="COMBA;COMBA;BASIC;SLIDE;BASIC;BASIC" \
	-DED_PRECO=off \
	-DEP_PRECO=off \
	-DTIMER=CYCLE \
	-DAMALG=on \
	-DMD_METHD=BLAKE2S_256 \
	-DBENCH=0 \
	-DTESTS=0 $WD_ROOT/3rdParty/relic
make -j 7
cd ..

arm-linux-gnueabihf-g++ -O3 -std=c++11 -DPRETTY_PRINTER -Drestrict=__restrict__ \
	-Irelic/include \
	-I$WD_ROOT/3rdParty/relic/include \
	-I$WD_ROOT/3rdParty/libcbor/src \
	-I$WD_ROOT/3rdParty/libtins/include \
	-Irelic/include \
	-I$WD_ROOT/3rdParty/easyloggingpp/src \
	-I$WD_ROOT/3rdParty/NORX/norx3261/ref \
	-I/Volumes/tank/pi_gateway/usr/include \
	-I/Volumes/tank/pi_gateway/usr/include/arm-linux-gnueabihf \
	-L/Volumes/tank/pi_gateway/usr/lib \
	-L/Volumes/tank/pi_gateway/lib/arm-linux-gnueabihf \
	-L/Volumes/tank/pi_gateway/usr/lib/arm-linux-gnueabihf \
	-I$WD_ROOT/common \
	-Lrelic/lib \
	-Llibcbor/src \
	-Llibtins/lib \
	../main.cpp \
	-lrelic_s \
	-lcbor \
	-ltins \
	-lpthread \
	-lboost_system \
	-lboost_program_options \
	-lnfnetlink -lnetfilter_queue -lpcap \
	-o gateway
#scp gateway pi@141.22.28.242:/home/pi/gateway
scp gateway pi@raspberrypi:/home/pi/gateway
