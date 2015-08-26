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

INITIALIZE_EASYLOGGINGPP

// library headers
#include <cbor.h>
extern "C" {
	#include <relic.h>
}

inline MAKE_LOGGABLE(fp_t, n, os) {
	std::vector<char> str;
	str.resize(100);
	fp_write_str(str.data(), 100, n, 10);
	std::string s(str.data());
	os << s;
	return os;
}

inline MAKE_LOGGABLE(ec_t, p, os) {
	os << "ec_t(" << p->x << ", " << p->y << ", " << p->z << ")";
	return os;
}

#include <cstdio>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/thread.hpp>

#include <unistd.h>
#include <signal.h>

std::string byteVecToStr(const std::vector<uint8_t>& data) {
	std::string str;
	for (int n = 0; n < data.size(); n++) {
		char byteStr[3];
		sprintf(byteStr, "%02X", data[n]);
		str += byteStr;
	}
	return str;
}

// other headers
#include "ibc.h"
#include "../gateway/network.h"
#include "network_interface.h"
#include "ta_lookup_responder.h"
#include "iot_service.h"
#include "ta_lookup_cache.h"

// other sources
#include "ibc.cpp"
#include "../gateway/network.cpp"
#include "network_interface.cpp"
#include "ta_lookup_responder.cpp"
#include "ta_lookup_cache.cpp"
#include "iot_service.cpp"
#include "relic_cbor.c"

extern "C" {
	#include "norx.c"
}

boost::asio::io_service io_service;
bool stop = false;

void my_handler(int s){
	LOG(INFO) << "Caught signal: " << s;
	stop = true;
	io_service.stop();
}

using namespace std;

namespace po = boost::program_options;

static std::vector<uint8_t> vectorFromFile(char const* filename) {
	ifstream ifs(filename, ios::binary|ios::ate);
	ifstream::pos_type pos = ifs.tellg();

	std::vector<uint8_t>  result(pos);

	ifs.seekg(0, ios::beg);
	ifs.read(reinterpret_cast<char*>(result.data()), pos);

	return result;
}


void network_thread() {
	LOG(INFO) << "Start network event loop.";
	try {
		io_service.run();
	}
	catch (std::exception& e) {
		LOG(INFO) << e.what();
		el::base::debug::StackTrace();
	}
	LOG(INFO) << "Network event loop done.";
}

int main(int argc, char* argv[]) {
	START_EASYLOGGINGPP(argc, argv);
	el::Loggers::reconfigureAllLoggers(el::ConfigurationType::Format, "%datetime %level %loc : %msg");

	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = my_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);

	LOG(INFO) << "IBC-based End-to-End Authentication Gateway for the Internet of Things";

	po::options_description desc("Allowed options");
	desc.add_options()
		("help", "show help message")
		("interface", po::value<std::string>(), "network interface to bind to")
		("prefix", po::value<std::string>(), "IPv6 network prefix (48 bit) to use");

	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm);

	if (vm.count("help")) {
		std::cout << desc << "\n";
		return 0;
	}

	std::string interface;
	if (vm.count("interface")) {
		interface = vm["interface"].as<std::string>();
	}
	if (interface.empty()) {
		LOG(ERROR) << "An interface has to be specified (--interface)";
		return 1;
	}

	std::string prefixString;
	if (vm.count("prefix")) {
		prefixString = vm["prefix"].as<std::string>();
	}

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

	try {
		std::shared_ptr<NetworkInterface> ni = std::make_shared<NetworkInterface>(boost::asio::ip::address::from_string("fd2d:0388:abcd::").to_v6());
		ni->configureInterface(interface, ta);
		
		// start dynamic configuration server (part of this authentication support server)
		std::shared_ptr<DynamicConfigurationServer> dcs = std::make_shared<DynamicConfigurationServer>(io_service, ni, ta);
		
		// start TA lookup responder (part of this authentication support server)
		std::shared_ptr<TALookupResponder> talr = std::make_shared<TALookupResponder>(io_service, ni, ta);

		std::array<uint8_t, 16> serverID = ni->getUsedAddress().to_bytes();
		serverID[14] = 0;
		serverID[15] = 0xab;

		std::shared_ptr<IoTService> iotService = std::make_shared<IoTService>(io_service, serverID, ta->extractIdentityKey(std::vector<uint8_t>(serverID.begin(), serverID.end())));

		boost::thread networkThread(network_thread);

		// prompt loop
		//char *line = NULL;
		std::string line; 
		while(true/* (line = linenoise("> ")) != NULL*/) {
			printf("> ");
			std::getline(std::cin, line);
			std::string lineStr(line);

			bool unknownCommand = false;
			if (lineStr == "exit") {
				io_service.stop();
				break;
			}
			else if (lineStr == "query") {
				iotService->sendQuery("fd2d:388:6a7b:d4e8:9739:f1ac:aed5:5", "rnd");
			}
			else if (lineStr == "cache") {
				iotService->getCache()->printCache();
			}
			else {
				printf("Unknown command.\n");
				unknownCommand = true;
			}
			if (!unknownCommand) {
				exit(1);
			}
			line = "";
			//free(line);
		}

		networkThread.join();
	}
	catch (std::exception& e) {
		LOG(INFO) << e.what();
		el::base::debug::StackTrace();
	}


	LOG(INFO) << "Clean up RELIC...";
	core_clean();
	return 0;
}