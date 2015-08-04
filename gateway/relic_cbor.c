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

#include "relic_cbor.h"

cbor_item_t* relic_bn2cbor(const bn_t n) {
	int size = bn_size_bin(n);
	uint8_t* data = (uint8_t*)malloc(size);
	cbor_item_t* ret = NULL;
	bn_write_bin(data, size, n);
	ret = cbor_build_bytestring(data, size);
	free(data);
	return ret;
}

cbor_item_t* relic_fp2cbor(const fp_t n) {
	int size = FP_BYTES;
	uint8_t* data = (uint8_t*)malloc(size);
	cbor_item_t* ret = NULL;
	fp_write_bin(data, size, n);
	ret = cbor_build_bytestring(data, size);
	free(data);
	return ret;
}

cbor_item_t* relic_ec2cbor(const ec_t n) {
	ec_t tmp;
	cbor_item_t* ret = NULL;
	
	ec_null(tmp);
	ec_new(tmp);
	ec_norm(tmp, n);

	ret = cbor_new_definite_map(2);

	// add X coordinate
	cbor_map_add(ret, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("x")),
		.value = cbor_move(relic_fp2cbor(tmp->x))
	});

	// add Y coordinate
	cbor_map_add(ret, (struct cbor_pair) {
		.key = cbor_move(cbor_build_string("y")),
		.value = cbor_move(relic_fp2cbor(tmp->y))
	});

	ec_free(tmp);
	return ret;
}

void relic_cbor2bn(bn_t n, const cbor_item_t* item) {
	assert(cbor_isa_bytestring(item));
	int size = cbor_bytestring_length(item);
	bn_read_bin(n, cbor_bytestring_handle(item), size);
}

void relic_cbor2fp(fp_t n, const cbor_item_t* item) {
	assert(cbor_isa_bytestring(item));
	int size = cbor_bytestring_length(item);
	fp_read_bin(n, cbor_bytestring_handle(item), size);
}

void relic_cbor2ec(ec_t n, const cbor_item_t* item) {
	assert(cbor_isa_map(item));
	size_t pairs = cbor_map_size(item);
	ec_null(n);
	fp_set_dig(n->z, 1);
	for (cbor_pair* pair = cbor_map_handle(item); pairs > 0; pair++, pairs--) {
		if (strncmp(reinterpret_cast<char*>(cbor_string_handle(pair->key)), "x", 1)) {
			relic_cbor2fp(n->x, pair->value);
		}
		else if (strncmp(reinterpret_cast<char*>(cbor_string_handle(pair->key)), "y", 1)) {
			relic_cbor2fp(n->y, pair->value);
		}
	}
}

