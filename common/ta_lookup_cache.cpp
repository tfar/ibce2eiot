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

#include "ta_lookup_cache.h"

TALookupCache::TALookupCache(boost::asio::io_service& ioservice, std::array<uint8_t, 16> address) {
	sleep(5);
	int fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	struct sockaddr_in6 serv_addr;
	serv_addr.sin6_family=AF_INET6;
	serv_addr.sin6_port=htons(4224);
	memcpy(&serv_addr.sin6_addr, address.data(), address.size());

	serv_addr.sin6_flowinfo=0;
	serv_addr.sin6_scope_id=0;
	bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

	socket_ = std::make_shared<boost::asio::ip::udp::socket>(ioservice);
	/*boost::asio::ip::udp::endpoint endpoint = boost::asio::ip::udp::endpoint(networkInterface_->getUsedAddress(), 4224);
	LOG(INFO) << endpoint;
	system("ifconfig");
	socket_->open(endpoint.protocol());
	socket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));
	socket_->bind(endpoint);*/
	socket_->assign(boost::asio::ip::udp::v6(), fd);
}

std::tuple<bool, ec> TALookupCache::getTAKeyOrRequest(std::array<uint8_t, 16> address) {
	std::array<uint8_t, 14> prefix;
	memcpy(prefix.data(), address.data(), 14);
	return getTAKeyOrRequest(prefix);
}

std::tuple<bool, ec> TALookupCache::getTAKeyOrRequest(std::array<uint8_t, 14> prefix) {
	std::tuple<bool, ec> result;
	std::get<0>(result) = false;

	auto lookup = lookupCache_.find(prefix);
	if (lookup == lookupCache_.end()) {
		LOG(INFO) << "Cache miss. Send TA parameter lookup request.";
		requestTA(prefix);
	}
	else {
		LOG(INFO) << "Cache hit.";
		std::get<0>(result) = true;
		std::get<1>(result) = lookup->second;
	}

	return result;
}

size_t TALookupCache::cacheSize() {
	return lookupCache_.size();
}

void TALookupCache::printCache() {
	auto i = lookupCache_.begin();
	LOG(INFO) << "Cache";
	LOG(INFO) << "=====";
	while (i != lookupCache_.end()) {
		std::array<uint8_t, 16> tmpAddr;
		memset(tmpAddr.data(), 0, tmpAddr.size());
		memcpy(tmpAddr.data(), i->first.data(), 14);

		boost::asio::ip::address_v6 remotePrefixAddr(tmpAddr);
		LOG(INFO) << remotePrefixAddr << " --> " << i->second.p;
		i++;
	}
}

void TALookupCache::handleRequestReceived(const boost::system::error_code& error, size_t bytes_transferred) {
	LOG(INFO) << "received TA lookup response from " << remote_endpoint_;

	std::array<uint8_t, 6 + 35> prefixPlusTA;
	boost::asio::ip::address_v6::bytes_type remoteAddrBytes = remote_endpoint_.address().to_v6().to_bytes();
	memcpy(prefixPlusTA.data(), remoteAddrBytes.data(), 6);
	memcpy(prefixPlusTA.data() + 6, recv_buffer_.data(), 35);


	uint8_t hash[MD_LEN];
	md_map(hash, (uint8_t*)prefixPlusTA.data(), prefixPlusTA.size());
	if (util_cmp_const((uint8_t*)(remoteAddrBytes.data()) + 6, hash, 8) == CMP_EQ) {
		LOG(INFO) << "received TA public key is valid";
		std::array<uint8_t, 14> prefix;
		memcpy(prefix.data(), remoteAddrBytes.data(), 14);

		struct cbor_load_result result;
		cbor_item_t* item = cbor_load((uint8_t*)recv_buffer_.data(), bytes_transferred, &result);
		ec taPK;
		relic_cbor2ec_compressed(taPK.p, item);
		cbor_decref(&item);
		LOG(INFO) << "Public key for " << remote_endpoint_ << " is " << taPK.p;
		if (lookupCache_.find(prefix) != lookupCache_.end()) {
			LOG(INFO) << "Cached public key already present.";
		}
		else {
			LOG(INFO) << "Pin(Cache) received prefix/public key binding for TA";
			lookupCache_[prefix] = taPK;
			onTAKeyAvailable(prefix, taPK);
		}
	}
	else {
		LOG(INFO) << "received TA public key is invalid";
	}
}

void TALookupCache::startReceive() {
	socket_->async_receive_from(
		boost::asio::buffer(recv_buffer_), remote_endpoint_,
		boost::bind(&TALookupCache::handleRequestReceived, this,
		  boost::asio::placeholders::error,
		  boost::asio::placeholders::bytes_transferred));
	LOG(INFO) << "Waiting for TA lookup reply on: " << socket_->local_endpoint();
}

void TALookupCache::requestTA(std::array<uint8_t, 14> prefix) {
	std::array<uint8_t, 16> remoteTAaddress;
	memcpy(remoteTAaddress.data(), prefix.data(), prefix.size());
	remoteTAaddress[14] = 0x00;
	remoteTAaddress[15] = 0x01;

	cbor_item_t* root = cbor_build_string("TAL");
	unsigned char* buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);	

	boost::asio::ip::address_v6 remoteTALookupService(remoteTAaddress);
	boost::system::error_code error;
	LOG(INFO) << "Send TA lookup request to " << remoteTALookupService;
	socket_->send_to(boost::asio::buffer(buffer, length), boost::asio::ip::udp::endpoint(remoteTALookupService, 4224), 0, error);
	free(buffer);

	cbor_decref(&root);
	if (error) {
		LOG(INFO) << "Error: " << error << " : " << error.message();
	}
	startReceive();
}
