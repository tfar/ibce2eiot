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

#pragma once

#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "ta_lookup_cache.h"

class IoTService {
public:
	IoTService(boost::asio::io_service& ioservice, const std::array<uint8_t, 16>& id, IBC_User user);

	void sendMessage(const std::string& message);
	void sendQuery(const std::string& target, const std::string& message);

	std::shared_ptr<TALookupCache> getCache();

private:
	void startReceive();
	void handleMessageReceived(const boost::system::error_code& error, size_t bytes_transferred);

	void authenticateMessage(boost::asio::ip::address_v6 senderAddress, std::vector<uint8_t> data, ec taKey);
	void handleDelayedAuthentication(boost::asio::ip::udp::endpoint remoteEndpoint, std::vector<uint8_t> data, std::array<uint8_t, 14> taPrefix, ec taKey);

private:
	std::shared_ptr<TALookupCache> lookupCache_;

	std::shared_ptr<boost::asio::ip::udp::socket> socket_;
	std::array<uint8_t, 16> id_;
	std::shared_ptr<IBC_User> ibcUser_;

	boost::asio::ip::udp::endpoint remote_endpoint_;
	std::array<char, 200> recv_buffer_;

	std::vector<std::tuple<>> cachedMessages_;
};