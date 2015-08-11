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

#include "network.h"

#include <boost/bind.hpp>

#include <array>

#include "norx.hpp"

const uint8_t confRequestKey[16] = {0x82, 0x02, 0x1a, 0xb1, 0x47, 0xd8, 0xbb, 0x75, 0x91, 0x17, 0x4d, 0x9c, 0x81, 0x74, 0x3e, 0x3b, };
const uint8_t confResponseKey[16] = {0xbe, 0x87, 0x7c, 0x23, 0xf0, 0x6c, 0x59, 0x69, 0x92, 0xda, 0xe9, 0xd1, 0xf2, 0xf9, 0x36, 0x7c, };

std::array<unsigned char, 16> dynamicConfigAddressListen = {0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x2e, 0x0e, 0xcc};
static boost::asio::ip::address_v6 configListenAddress = boost::asio::ip::address_v6(dynamicConfigAddressListen, 0x2);

DynamicConfigurationServer::DynamicConfigurationServer(boost::asio::io_service& ioservice, std::shared_ptr<NetworkInterface> netInf, std::shared_ptr<TA> ta) :
		networkInterface_(netInf), ta_(ta) {
	socket_ = std::make_shared<boost::asio::ip::udp::socket>(ioservice);
	boost::asio::ip::udp::endpoint endpoint = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string("0::0"), 4223);
	socket_->open(endpoint.protocol());
	socket_->set_option(boost::asio::ip::udp::socket::reuse_address(true));
	socket_->bind(endpoint);
	socket_->set_option(boost::asio::ip::multicast::join_group(configListenAddress, 4));
	startReceive();

	const uint8_t testData[] = {
		0x82, 0x50, 0x60, 0xe1, 0x0b, 0xc5, 0x2c, 0xbe, 0xf6, 0x27, 
		0x5e, 0x6e, 0x5e, 0x63, 0x45, 0x81, 0x25, 0x20, 0x54, 0x06, 
		0x8b, 0x66, 0xb1, 0xf6, 0xd2, 0xb0, 0x43, 0xce, 0x57, 0x74, 
		0x05, 0xa1, 0x62, 0xcb, 0xa1, 0x66, 0x30, 0x60, 0xe1};
/*
	memcpy(recv_buffer_.data(), testData, 39);
	boost::system::error_code error;
	handleRequestReceived(error, 39);
	*/
}

void DynamicConfigurationServer::startReceive() {
	socket_->async_receive_from(
		boost::asio::buffer(recv_buffer_), remote_endpoint_,
		boost::bind(&DynamicConfigurationServer::handleRequestReceived, this,
		  boost::asio::placeholders::error,
		  boost::asio::placeholders::bytes_transferred));
	LOG(INFO) << "Waiting for dynamic configuration requests on: " << socket_->local_endpoint();
}

void DynamicConfigurationServer::handleRequestReceived(const boost::system::error_code& error, size_t bytes_transferred) {
	LOG(INFO) << "Request received from " << remote_endpoint_;

	struct cbor_load_result result;
	cbor_item_t* item = cbor_load((uint8_t*)recv_buffer_.data(), bytes_transferred, &result);

	size_t items = cbor_array_size(item);
	assert(items == 2);

	cbor_item_t* nonceItem = cbor_array_get(item, 0);
	cbor_item_t* ciphertextItem = cbor_array_get(item, 1);

	cbor_describe(item, stdout);
	fflush(stdout);

	std::array<uint8_t, 16> nonce;
	memcpy(nonce.data(), cbor_bytestring_handle(nonceItem), 16);

	std::vector<uint8_t> ciphertext;
	ciphertext.resize(cbor_bytestring_length(ciphertextItem));
	memcpy(ciphertext.data(), cbor_bytestring_handle(ciphertextItem), ciphertext.size());

	std::array<uint8_t, 16> requestKey;
	memcpy(requestKey.data(), confRequestKey, 16);
	std::tuple<bool, std::vector<uint8_t> > plaintext = NORX::decrypt(
		std::vector<uint8_t>(), 
		ciphertext,
		std::vector<uint8_t>(),
		nonce,
		requestKey);
	cbor_decref(&item);

	if (std::get<0>(plaintext)) {
		LOG(INFO) << "decryption successful";
		item = cbor_load((uint8_t*)std::get<1>(plaintext).data(), std::get<1>(plaintext).size(), &result);

		//LOG(INFO) << "plaintext: " << byteVecToStr(std::get<1>(plaintext));

		if (strncmp("REQ", (const char*)cbor_string_handle(item), 3) == 0) {
			LOG(INFO) << "received correct request";
			generateCredentialsAndSendResponse(nonce);
		}
		else {
			cbor_describe(item, stdout);
		}
		fflush(stdout);

		/* Deallocate the result */
		cbor_decref(&item);
	}
	else {
		LOG(ERROR) << "failed decrypting dynamic initialisation request.";
		LOG(ERROR) << "ciphertext: " << byteVecToStr(ciphertext);
		LOG(ERROR) << "nonce:      " << byteVecToStr(std::vector<uint8_t>(nonce.begin(), nonce.end()));
	}
	startReceive();
}

void DynamicConfigurationServer::handleSend(const boost::system::error_code& /*error*/,
      std::size_t /*bytes_transferred*/)
{
}

void DynamicConfigurationServer::generateCredentialsAndSendResponse(const std::array<uint8_t, 16>& nonce) {
	LOG(INFO) << "generate ID";
	// statically use node ID 5
	std::array<uint8_t, 16> nodeID = networkInterface_->getUsedAddress().to_bytes();
	nodeID[14] = 0x0;
	nodeID[15] = 0x5;
	boost::asio::ip::address_v6 nodeAddress = boost::asio::ip::address_v6(nodeID);

	LOG(INFO) << "extract identity key for ID: " << nodeAddress.to_string();
	auto idKey = ta_->extractIdentityKey(std::vector<uint8_t>(nodeID.begin(), nodeID.end()));

	LOG(INFO) << "encode response in CBOR";
	// build cbor message of TA public key, identity and identity key
	std::vector<uint8_t> clearBuffer;

	ec_t mpk;

	ec_null(mpk); ec_new(mpk);

	cbor_item_t* root = cbor_new_definite_map(3);
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("mpk")),
		.value = cbor_move(relic_ec2cbor_compressed(ta_->kgc_->mpk))
	});
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("id")),
		.value = cbor_move(cbor_build_bytestring(nodeID.data(), nodeID.size()))
	});

	cbor_item_t* idKey_cbor = cbor_new_definite_array(2);
	cbor_array_push(idKey_cbor, cbor_move(relic_ec2cbor_compressed(idKey.user->R)));
	cbor_array_push(idKey_cbor, cbor_move(relic_bn2cbor(idKey.user->s)));

	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("key")),
		.value = cbor_move(idKey_cbor)
	});

	cbor_describe(root, stdout);
	fflush(stdout);

	unsigned char* buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

	clearBuffer.resize(length);
	memcpy(clearBuffer.data(), buffer, length);
	free(buffer);

	// encrypt reply
	LOG(INFO) << "encrypt dynamic configuration reply";
	std::array<uint8_t, 16> responseKey;
	memcpy(responseKey.data(), confResponseKey, 16);

	std::vector<uint8_t> ciphertext = NORX::encrypt(
		std::vector<uint8_t>(), 
		clearBuffer,
		std::vector<uint8_t>(),
		nonce,
		responseKey);

	LOG(INFO) << "Plain response: " << byteVecToStr(clearBuffer);

	LOG(INFO) << "Encrypted response: " << byteVecToStr(ciphertext);

	// send reply
	//LOG(INFO) << "send response to " << remote_endpoint_.address().to_string();
	socket_->async_send_to(boost::asio::buffer(ciphertext), remote_endpoint_,
          boost::bind(&DynamicConfigurationServer::handleSend, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred));
    /*
    socket_->async_send_to(boost::asio::buffer(std::string("This is just a test message.")), remote_endpoint_,
          boost::bind(&DynamicConfigurationServer::handleSend, this,
            boost::asio::placeholders::error,
            boost::asio::placeholders::bytes_transferred));*/

	ec_free(mpk);
}