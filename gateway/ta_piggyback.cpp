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


// iptables -A INPUT -p udp --match multiport --dports 4222:4224 -j NFQUEUE --queue-num 0

#include "ta_piggyback.h"

#include <linux/netfilter.h>
#include <pcap.h>
#include <tins/tins.h>

#define BUFSIZE 2048
// pcap file descriptor
pcap_dumper_t *p_output;
int use_pcap = 0;

/* Definition of callback function */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
	TAPiggyBack* tapb = reinterpret_cast<TAPiggyBack*>(data);
	return tapb->handle_incoming_packet(qh, nfmsg, nfa);
}

int TAPiggyBack::handle_incoming_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa) {
    int verdict;
    u_int32_t id;
	nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
	if (ph) {
 		id = ntohl(ph->packet_id);
	}

	char* payloadData;
	int len = nfq_get_payload(nfa, &payloadData);
	verdict = NF_ACCEPT;
	if (len > 0) {
		Tins::RawPDU pdu =	Tins::RawPDU((uint8_t*)payloadData, len);

		Tins::IPv6 ipv6 = pdu.to<Tins::IPv6>();
		auto src_addr = ipv6.src_addr();
		std::array<uint8_t, 14> srcPrefix;
		memcpy(srcPrefix.data(), src_addr.begin(), srcPrefix.size());

		LOG(INFO) << "Intercepted authenticated packet from " << src_addr;
		// only do TA key piggyback for incoming messages
		if (srcPrefix != localPrefix_) {
			verdict = NF_DROP;
			std::array<uint8_t, 16> src_addr_array;
			std::array<uint8_t, 14> taPrefix;
			memcpy(src_addr_array.data(), src_addr.begin(), src_addr_array.size());
			memcpy(taPrefix.data(), src_addr_array.data(), taPrefix.size());
			std::tuple<bool, ec> taLookupResult = lookupCache_->getTAKeyOrRequest(src_addr_array);
			if (std::get<0>(taLookupResult)) {
				LOG(INFO) << "Cache hit";
				sendTALookupResponseAndData(taPrefix, std::get<1>(taLookupResult), ipv6);
			}
			else {
				LOG(INFO) << "Cache miss";
				lookupCache_->onTAKeyAvailable.connect(boost::bind(&TAPiggyBack::handleTALookupResponse, this, _1, _2, ipv6.serialize()));
			}
		}
		else {
			LOG(INFO) << "Pass through outgoing message";
		}
	}

	return nfq_set_verdict(qh, id, verdict, 0, NULL); /* Verdict packet */
}

void TAPiggyBack::sendTALookupResponseAndData(std::array<uint8_t, 14> taPrefix, ec taKey, Tins::IPv6 originalPacket) {
	LOG(INFO) << "Send locally generated TA lookup result and original packet.";
	LOG(INFO) << "Begin generating packet";
	std::array<uint8_t, 16> dstArray;
	memcpy(dstArray.data(), originalPacket.dst_addr().begin(), dstArray.size());
	Tins::IPv6 taLookupResponse = generateTALookupResponse(taPrefix, taKey, dstArray);
	LOG(INFO) << "End generating packet";

	Tins::PacketSender sender;
	sender.send(taLookupResponse);
	sender.send(originalPacket);
}

void TAPiggyBack::handleTALookupResponse(std::array<uint8_t, 14> taPrefix, ec taKey, std::vector<uint8_t> originalPacket) {
	sendTALookupResponseAndData(taPrefix, taKey, Tins::IPv6(originalPacket.data(), originalPacket.size()));
	lookupCache_->onTAKeyAvailable.disconnect(boost::bind(&TAPiggyBack::handleTALookupResponse, this, _1, _2, originalPacket));
}


Tins::IPv6 TAPiggyBack::generateTALookupResponse(std::array<uint8_t, 14> TAprefix, ec taKey, std::array<uint8_t, 16> to) {
	std::array<uint8_t, 16> remoteTAResponderAddress;
	memcpy(remoteTAResponderAddress.data(), TAprefix.data(), 14);
	remoteTAResponderAddress[14] = 0x0;
	remoteTAResponderAddress[15] = 0x1;

	Tins::IPv6 lookupResponsePacket = Tins::IPv6();
	lookupResponsePacket.src_addr(remoteTAResponderAddress.data());
	lookupResponsePacket.dst_addr(to.begin());

	std::vector<uint8_t> taAsCBOR;

	cbor_item_t* root = cbor_move(relic_ec2cbor_compressed(taKey.p));
	unsigned char* buffer = NULL;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);
	taAsCBOR.resize(length);
	memcpy(taAsCBOR.data(), buffer, length);
	free(buffer);
	cbor_decref(&root);

	Tins::UDP udpPacket = Tins::UDP();
	udpPacket.sport(4224);
	udpPacket.dport(4224);

	Tins::RawPDU cbor = Tins::RawPDU(taAsCBOR.data(), taAsCBOR.size());
	udpPacket.inner_pdu(cbor);

	lookupResponsePacket.inner_pdu(udpPacket);
	return lookupResponsePacket;
}

TAPiggyBack::TAPiggyBack(boost::asio::io_service& ioservice, boost::asio::ip::address_v6 address) {
	lookupCache_ = std::make_shared<TALookupCache>(ioservice, address.to_bytes());
	system("ip6tables -I FORWARD -p udp --dport 4222 -j NFQUEUE --queue-num 0");
	stop_  = false;

	auto addressArray = address.to_bytes();
	memcpy(localPrefix_.data(), addressArray.data(), localPrefix_.size());

	LOG(INFO) << "Starting thread";
	thread_ = std::thread(&TAPiggyBack::threadWrapper, this);
}

TAPiggyBack::TAPiggyBack(std::shared_ptr<TALookupResponder> lookupResponder, boost::asio::ip::address_v6 address) {
	lookupCache_ = std::make_shared<TALookupCache>(lookupResponder);
	system("ip6tables -I FORWARD -p udp --dport 4222 -j NFQUEUE --queue-num 0");
	stop_  = false;

	auto addressArray = address.to_bytes();
	memcpy(localPrefix_.data(), addressArray.data(), localPrefix_.size());

	LOG(INFO) << "Starting thread";
	thread_ = std::thread(&TAPiggyBack::threadWrapper, this);
}

TAPiggyBack::~TAPiggyBack() {
	stop_ = true;
	LOG(INFO) << "waiting for worker thread to finish";
	thread_.join();
	system("ip6tables -D FORWARD -p udp --dport 4222 -j NFQUEUE --queue-num 0");
}

void TAPiggyBack::threadWrapper(TAPiggyBack* ptr) {
	ptr->run();
}


void TAPiggyBack::run() {
	LOG(INFO) <<  "opening library handle";
	nfqHandle_ = nfq_open();
	if (!nfqHandle_) {
		LOG(ERROR) << "error during nfq_open()";
		exit(1);
	}

	LOG(INFO) << "unbinding existing nf_6queue handler for AF_INET6 (if any)";
	if (nfq_unbind_pf(nfqHandle_, AF_INET6) < 0) {
		LOG(ERROR) << "error during nfq_unbind_pf()";
		exit(1);
	}

	LOG(INFO) << "binding nfnetlink_queue as nf_queue handler for AF_INET6";
	if (nfq_bind_pf(nfqHandle_, AF_INET6) < 0) {
		LOG(ERROR) <<  "error during nfq_bind_pf()";
		exit(1);
	}

	/* Set callback function */
	int rv;
	nfnl_handle *nh;
	nh = nfq_nfnlh(nfqHandle_);
	char buf[BUFSIZE];

	qh = nfq_create_queue(nfqHandle_, 0, &cb, this);
	
	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		LOG(ERROR) << "can't set packet_copy mode";
		exit(1);
	}


	int fd = nfq_fd(nfqHandle_);

	timeval tv;
	tv.tv_sec = 2;  /* 30 Secs Timeout */
	tv.tv_usec = 0;  // Not init'ing this can cause strange errors


	LOG(INFO) << "Start filtering on fd: " << fd;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
	while(!stop_) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			LOG(INFO) << "handle packet";
			nfq_handle_packet(nfqHandle_, buf, rv); /* send packet to callback */
			continue;
		}
	}

	LOG(INFO) << "unbinding from queue 0";
	nfq_destroy_queue(qh);

	LOG(INFO) << "closing library handle";
	nfq_close(nfqHandle_);
}