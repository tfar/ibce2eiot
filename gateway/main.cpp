/*
The MIT License (MIT)

Copyright (c) 2015 Tobias Markmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <easylogging++.h>

// library headers
extern "C" {
	#include <cbor.h>
	#include <relic.h>
}

#include <cstdio>
#include <fstream>

#include <unistd.h>

// other headers
#include "ibc.h"

// other sources
#include "ibc.cpp"
#include "relic_cbor.c"

INITIALIZE_EASYLOGGINGPP

std::string byteVecToStr(const std::vector<uint8_t>& data) {
	std::string str;
	for (int n = 0; n < data.size(); n++) {
		char byteStr[3];
		sprintf(byteStr, "%X", data[n]);
		str += byteStr;
	}
	return str;
}

using namespace std;

static std::vector<uint8_t> vectorFromFile(char const* filename) {
    ifstream ifs(filename, ios::binary|ios::ate);
    ifstream::pos_type pos = ifs.tellg();

    std::vector<uint8_t>  result(pos);

    ifs.seekg(0, ios::beg);
    ifs.read(reinterpret_cast<char*>(result.data()), pos);

    return result;
}


int main(int argc, char* argv[]) {
	START_EASYLOGGINGPP(argc, argv);
	LOG(INFO) << "IBC-based End-to-End Authentication Gateway for the Internet of Things";

	LOG(INFO) << "Initialize RELIC...";
	core_init();

	LOG(INFO) << "Set elliptic curve...";
	ec_param_set_any();

	LOG(INFO) << "RELIC configuration:";
	conf_print();

	shared_ptr<TA> ta;
	if( access("ta.private.cbor", F_OK ) != -1 ) {
		LOG(INFO) << "Reading existing TA config from ta.private.cbor...";
		ta = TA::load(vectorFromFile("ta.private.cbor"));
	}
	else {
		LOG(INFO) << "No existing TA config found. Generating new TA...";
		ta = TA::init();

		LOG(INFO) << "Save TA config to ta.private.cbor...";
		std::vector<uint8_t> taAsCbor = ta->save();

		ofstream outfile("ta.private.cbor", ios::out | ios::binary); 
		outfile.write((char*)taAsCbor.data(), taAsCbor.size());
	}

	LOG(INFO) << "Clean up RELIC...";
	core_clean();
	return 0;
}