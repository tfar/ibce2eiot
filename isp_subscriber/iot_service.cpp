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

#include "iot_service.h"

#include "relic_cbor.h"

#include <boost/asio.hpp>

IoTService::IoTService(boost::asio::io_service& ioservice, const std::array<uint8_t, 16>& id, IBC_User user) : id_(id), ibcUser_(std::make_shared<IBC_User>(user)) {
/*	int fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	struct sockaddr_in6 serv_addr;
	serv_addr.sin6_family=AF_INET6;
	serv_addr.sin6_port=htons(4222);
	memcpy(&serv_addr.sin6_addr, id.data(), id.size());
	serv_addr.sin6_flowinfo=0;
	serv_addr.sin6_scope_id=0;
	bind(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

	socket_ = std::make_shared<boost::asio::ip::udp::socket>(ioservice);
	socket_->assign(boost::asio::ip::udp::v6(), fd);
	*/
	socket_ = std::make_shared<boost::asio::ip::udp::socket>(ioservice);
	boost::asio::ip::udp::endpoint endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v6(id), 4222);
	socket_->open(endpoint.protocol());
	socket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));
	socket_->bind(endpoint);
	LOG(INFO) << "local endpoint:" << socket_->local_endpoint();
}

void IoTService::sendMessage(const std::string& message) {

}

void IoTService::sendQuery(const std::string& target, const std::string& message) {
	LOG(INFO) << "Send signed query '" << message << "' to [" << target << "]:4222";
	auto idVec = std::vector<uint8_t>(id_.begin(), id_.end());
	auto data = std::vector<uint8_t>(message.begin(), message.end());
	LOG(INFO) << "Begin signing message";
	LOG(INFO) << "data len: " << data.size();
	Signature sig = Signature::sign(ibcUser_, idVec, data);
	LOG(INFO) << "End signing message";
	LOG(INFO) << "Begin CBOR encoding query";
	/*
		{
			msg: 'some message',
			sig: [ec, bn, bn]
		}
	*/
	cbor_item_t* root = cbor_new_definite_map(2);
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("msg")),
		.value = cbor_move(cbor_build_bytestring((unsigned char*)message.data(), message.size()))
	});
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("sig")),
		.value = cbor_move(sig.toCBORArray())
	});

#if defined(IOT_DEBUG)
	cbor_describe(root, stdout);
	fflush(stdout);
#endif

	unsigned char* buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);


	cbor_decref(&root);
	LOG(INFO) << "End CBOR encoding query";

	LOG(INFO) << "Begin sending query to " << target;
	boost::system::error_code error;
	socket_->send_to(boost::asio::buffer(buffer, length), boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(target).to_v6(), 4222), 0, error);
	if (error) {
		LOG(INFO) << "Error: " << error << " : " << error.message();
	}
	free(buffer);
	LOG(INFO) << "End sending query to " << target;
}
