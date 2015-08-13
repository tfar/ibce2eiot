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

#include "ta_lookup_responder.h"


TALookupResponder::TALookupResponder(boost::asio::io_service& ioservice, std::shared_ptr<NetworkInterface> networkInterface, std::shared_ptr<TA> ta) : networkInterface_(networkInterface), ta_(ta) {
	sleep(5);
	int fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);

	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	struct sockaddr_in6 serv_addr;
	serv_addr.sin6_family=AF_INET6;
	serv_addr.sin6_port=htons(4224);
	inet_pton(AF_INET6, networkInterface_->getUsedAddress().to_string().c_str(), &serv_addr.sin6_addr);
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
	startReceive();
}

void TALookupResponder::startReceive() {
	socket_->async_receive_from(
		boost::asio::buffer(recv_buffer_), remote_endpoint_,
		boost::bind(&TALookupResponder::handleRequestReceived, this,
		  boost::asio::placeholders::error,
		  boost::asio::placeholders::bytes_transferred));
	LOG(INFO) << "Waiting for TA lookup requests on: " << socket_->local_endpoint()	;
}

void TALookupResponder::handleRequestReceived(const boost::system::error_code& error, size_t bytes_transferred) {
	LOG(INFO) << "Request received from " << remote_endpoint_;
	
	// the TA public key as a simple CBOR bytestring
	LOG(INFO) << "encode response in CBOR";
	cbor_item_t* root = cbor_move(relic_ec2cbor_compressed(ta_->kgc_->mpk));

	unsigned char* buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

	std::vector<uint8_t> replyData(length);
	memcpy(replyData.data(), buffer, length);
	free(buffer);
	
	LOG(INFO) << "send TA parameters back";
	socket_->async_send_to(boost::asio::buffer(replyData), remote_endpoint_,
          boost::bind(&TALookupResponder::handleSend, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred));

	startReceive();
}

void TALookupResponder::handleSend(const boost::system::error_code& /*error*/, std::size_t /*bytes_transferred*/) {
	
}

void TALookupResponder::generateAndSendResponse() {

}