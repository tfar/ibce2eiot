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

#include "ta_lookup_cache.h"

#include <thread>
#include <memory>
#include <map>
#include <array>
#include <vector>

#include <tins/tins.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include "ta_lookup_responder.h"

class TAPiggyBack {
public:
	TAPiggyBack(boost::asio::io_service& ioservice, boost::asio::ip::address_v6 address);
	TAPiggyBack(std::shared_ptr<TALookupResponder> lookupResponder, boost::asio::ip::address_v6 address);
	~TAPiggyBack();

	void run();

	int handle_incoming_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa);

	static void threadWrapper(TAPiggyBack* ptr);

private:
	static void sendTALookupResponseAndData(std::array<uint8_t, 14> taPrefix, ec taKey, Tins::IPv6 originalPacket);
	static Tins::IPv6 generateTALookupResponse(std::array<uint8_t, 14> TAprefix, ec taKey, std::array<uint8_t, 16> to);

	void handleTALookupResponse(std::array<uint8_t, 14> taPrefix, ec taKey, std::vector<uint8_t>);

private:
	nfq_handle *nfqHandle_;
	nfq_q_handle *qh;
	std::thread thread_;
	bool stop_;

	std::array<uint8_t, 14> localPrefix_;
	std::shared_ptr<TALookupCache> lookupCache_;
};