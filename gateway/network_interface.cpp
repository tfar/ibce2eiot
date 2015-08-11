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

#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

extern "C" {
	#include "relic.h"
}

NetworkInterface::NetworkInterface(const boost::asio::ip::address_v6& prefix) : prefix_(prefix) {

}

NetworkInterface::~NetworkInterface() {
	// remove the IPv6 address from the interface
	LOG(INFO) << "Remove ip address " << usedAddress_.to_string() << " from interface " << interface_;
	char buffer[100];
	snprintf(buffer, 100, "ip address delete %s/112 dev %s", usedAddress_.to_string().c_str(), interface_.c_str());
	std::string ipAddressDeleteCmd(buffer);
	LOG(INFO) << "Run command: " << ipAddressDeleteCmd;
	system(ipAddressDeleteCmd.c_str());
}

void NetworkInterface::configureInterface(const std::string& interface, std::shared_ptr<TA> ta) {
	interface_ = interface;

	boost::asio::ip::address_v6::bytes_type addressBytes = prefix_.to_bytes();
	LOG(INFO) << "prefix: " << prefix_.to_string();

	std::array<uint8_t, 8> prefixPlusTAHash;

	std::vector<uint8_t> prefixPlusTA;
	prefixPlusTA.resize(7);
	memcpy(prefixPlusTA.data(), addressBytes.data(), 6);

	std::vector<uint8_t> pubKeyTA = ta->getPublicKey();
	prefixPlusTA.resize(prefixPlusTA.size() + pubKeyTA.size());
	memcpy(prefixPlusTA.data() + 6, pubKeyTA.data(), pubKeyTA.size());

	std::array<uint8_t, MD_LEN> hash;
	md_map(hash.data(), prefixPlusTA.data(), prefixPlusTA.size());
	memcpy(prefixPlusTAHash.data(), hash.data(), prefixPlusTAHash.size());

	memcpy(addressBytes.data() + 6, prefixPlusTAHash.data(), prefixPlusTAHash.size());
	addressBytes[addressBytes.size()-2] = 0x00;
	addressBytes[addressBytes.size()-1] = 0x01;

	usedAddress_ = boost::asio::ip::address_v6(addressBytes);
	char buffer[100];
	snprintf(buffer, 100, "ip address add %s/112 dev %s", usedAddress_.to_string().c_str(), interface.c_str());
	std::string ipAddressAddCmd(buffer);
	LOG(INFO) << "Run command: " << ipAddressAddCmd;
	system(ipAddressAddCmd.c_str());
}

boost::asio::ip::address_v6 NetworkInterface::getUsedAddress() const {
	return usedAddress_;
}

std::string NetworkInterface::getInterfaceName() const {
	return interface_;
}