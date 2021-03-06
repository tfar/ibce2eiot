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

#include <map>
#include <array>
#include <tuple>

#include <boost/signals2/signal.hpp>

class TALookupCache {
public:
	TALookupCache(boost::asio::io_service& ioservice, std::array<uint8_t, 16> address);
	TALookupCache(std::shared_ptr<TALookupResponder> taLookupResponder);

public:
	std::tuple<bool, ec> getTAKeyOrRequest(std::array<uint8_t, 16> address);
	std::tuple<bool, ec> getTAKeyOrRequest(std::array<uint8_t, 14> prefix);
	size_t cacheSize();
	void printCache();

	void handleTALookupResponse(boost::asio::ip::address_v6 from, std::vector<uint8_t> data);

private:
	void handleRequestReceived(const boost::system::error_code& error, size_t bytes_transferred);
	void startReceive();
	void requestTA(std::array<uint8_t, 14> prefix);

public:
	boost::signals2::signal<void (std::array<uint8_t, 14>, ec)> onTAKeyAvailable;

private:
	std::map<std::array<uint8_t, 14>, ec> lookupCache_;
	std::shared_ptr<boost::asio::ip::udp::socket> socket_;
	boost::asio::ip::udp::endpoint remote_endpoint_;
	std::array<char, 200> recv_buffer_;

	std::shared_ptr<TALookupResponder> taLookupResponder_;
};