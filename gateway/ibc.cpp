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

#include "ibc.h"

extern "C" {
	#include <cbor.h>
}

#include "relic_cbor.h"

TA::TA() {
	vbnn_ibs_kgc_null(kgc_);
	vbnn_ibs_kgc_new(kgc_);
}

TA::~TA() {
	vbnn_ibs_kgc_free(kgc_);
}

std::shared_ptr<TA> TA::init() {
	std::shared_ptr<TA> ta = std::make_shared<TA>();
	cp_vbnn_ibs_kgc_gen(ta->kgc_);
	LOG(INFO) << "New TA initialized, with public key: " << ta->kgc_->mpk;
	return ta;
}

std::shared_ptr<TA> TA::load(const std::vector<uint8_t>& data) {
	std::shared_ptr<TA> ta = std::make_shared<TA>();

	struct cbor_load_result result;
	cbor_item_t* item = cbor_load(data.data(), data.size(), &result);



	size_t pairs = cbor_map_size(item);
	for (cbor_pair* pair = cbor_map_handle(item); pairs > 0; pair++, pairs--) {
		if (strncmp(reinterpret_cast<char*>(cbor_string_handle(pair->key)), "mpk", 3) == 0) {
			relic_cbor2ec(ta->kgc_->mpk, pair->value);
		}
		else if (strncmp(reinterpret_cast<char*>(cbor_string_handle(pair->key)), "msk", 3) == 0) {
			relic_cbor2bn(ta->kgc_->msk, pair->value);
		}
	}
	/*
	relic_cbor2ec(kgc_->mpk, mpk->value);

	cbor_pair* msk = cbor_map_handle(cbor_move(cbor_build_string("msk")));
	relic_cbor2bn(kgc_->msk, msk->value);*/

	/* Deallocate the result */
	cbor_decref(&item);

	LOG(INFO) << "TA loaded, with public key: " << ta->kgc_->mpk;

	return ta;
}

std::vector<uint8_t> TA::save() {
	std::vector<uint8_t> res_buffer;

	cbor_item_t* root = cbor_new_definite_map(2);
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("mpk")),
		.value = cbor_move(relic_ec2cbor(kgc_->mpk))
	});
	cbor_map_add(root, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("msk")),
		.value = cbor_move(relic_bn2cbor(kgc_->msk))
	});

	unsigned char* buffer;
	size_t buffer_size, length = cbor_serialize_alloc(root, &buffer, &buffer_size);

	res_buffer.resize(length);
	memcpy(res_buffer.data(), buffer, length);
	free(buffer);

	cbor_decref(&root);

	return res_buffer;
}