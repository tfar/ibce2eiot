#!/usr/bin/env bash
set -e
WD_ROOT=$(git rev-parse --show-toplevel)

export CC=clang
export CXX=clang++

rm -rfd build
mkdir build
cd build

echo "Build libcbor"
mkdir libcbor
cd libcbor
cmake -DCMAKE_BUILD_TYPE=Release ../../../3rdParty/libcbor
make -j 6 cbor
cd ..

echo "Build RELIC"
mkdir relic
cd relic
cmake \
	-DCOMP="-O3 -pthread" \
	-DARCH=NONE \
	-OS=OSX \
	-DALIGN=1 \
	-DEC_METHD=EDWARD \
	-DFP_PRIME=255 \
	-DED_METHD="PROJC;LWNAF;LWNAF;BASIC" \
	-DSHLIB=off \
	-DBN_PRECI=512 \
	-DWORD=64 \
	-DWITH="ED;EC;MD;FP;BN;DV;CP;BC;EP" \
	-DBN_METHD="COMBA;COMBA;BASIC;SLIDE;BASIC;BASIC" \
	-DED_PRECO=off \
	-DEP_PRECO=off \
	-DTIMER=CYCLE \
	-DAMALG=on \
	-DMD_METHD=BLAKE2S_256 \
	-DBENCH=0 \
	-DTESTS=0 $WD_ROOT/3rdParty/relic
make -j 6
cd ..

#clang -O3 -c $WD_ROOT/3rdParty/linenoise/linenoise.c -o linenoise.o
clang++ -O3 -std=c++11 -DPRETTY_PRINTER -Drestrict=__restrict__ -pthread \
	-Irelic/include \
	-I$WD_ROOT/3rdParty/relic/include \
	-I$WD_ROOT/3rdParty/libcbor/src \
	-Irelic/include \
	-I$WD_ROOT/3rdParty/easyloggingpp/src \
	-I$WD_ROOT/3rdParty/NORX/norx3261/ref \
	-I$WD_ROOT/3rdParty/linenoise \
	-I$WD_ROOT/common \
	-Lrelic/lib \
	-Llibcbor/src \
	-DELPP_DISABLE_DEFAULT_CRASH_HANDLING \
	-DELPP_THREAD_SAFE \
	../main.cpp \
	-lrelic_s \
	-lcbor \
	-lboost_system \
	-lboost_program_options \
	-lboost_thread-mt \
	-o isp_subscriber
