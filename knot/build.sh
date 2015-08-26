#!/usr/bin/env bash
set -e
WD_ROOT=$(git rev-parse --show-toplevel)

echo "Build RELIC..."
rm -rf build
mkdir build
cd build
mkdir relic
cd relic
cmake \
	-DCMAKE_TOOLCHAIN_FILE=$WD_ROOT/knot/samr21-gcc.cmake \
	-DCOMP="-mcpu=cortex-m0plus -mlittle-endian -mthumb -mfloat-abi=soft -mno-thumb-interwork -ffunction-sections -fdata-sections -fno-builtin -fshort-enums -g3 -Os" \
	-DOPSYS=NONE \
	-DARCH=NONE \
	-DBENCH=0 \
	-DTESTS=0 \
	-DSHLIB=off \
	-DTIMER=CYCLE \
	-DAMALG=on \
	-DWORD=32 \
	-DWITH="ED;EC;MD;FP;BN;DV;CP" \
	-DRAND=HASH \
	-DSEED=ZERO \
	-DBN_PRECI=512 \
	-DBN_METHD="COMBA;COMBA;BASIC;SLIDE;BASIC;BASIC" \
	-DFP_PRIME=255 \
	-DEC_METHD=EDWARD \
	-DED_METHD="PROJC;LWNAF;LWNAF;BASIC" \
	-DED_PRECO=off \
	-DMD_METHD=BLAKE2S_256 \
	../../../3rdParty/relic
make
cd ..
cd ..

echo "Build RIOT..."
sudo env BOARD=samr21-xpro make clean 
env BOARD=samr21-xpro make -j 6
sudo env BOARD=samr21-xpro make flash