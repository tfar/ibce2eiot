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
#include <array>

#include <boost/asio.hpp>

#include "ibc.h"
#include "network_interface.h"

class TALookupResponder {
public:
	TALookupResponder(boost::asio::io_service& ioservice, std::shared_ptr<NetworkInterface> networkInterface, std::shared_ptr<TA> ta);

private:
	void startReceive();

	void handleRequestReceived(const boost::system::error_code& error, size_t bytes_transferred);
	void handleSend(const boost::system::error_code& /*error*/,
      std::size_t /*bytes_transferred*/);

	void generateAndSendResponse();

private:
	std::shared_ptr<boost::asio::ip::udp::socket> socket_;
	boost::asio::ip::udp::endpoint remote_endpoint_;
	std::array<char, 100> recv_buffer_;

	std::shared_ptr<TA> ta_;
	std::shared_ptr<NetworkInterface> networkInterface_;
};