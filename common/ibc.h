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

extern "C" {
	#include <relic.h>
}

#include "relic_cbor.h"

#include <memory>
#include <vector>

class IBC_User {
public:
	IBC_User() {
		vbnn_ibs_user_null(user);
		vbnn_ibs_user_new(user);
	}

	IBC_User( const IBC_User& other ) {
		vbnn_ibs_user_null(user);
		vbnn_ibs_user_new(user);

		ec_copy(user->R, other.user->R);
		bn_copy(user->s, other.user->s);
	}

	IBC_User( IBC_User& other ) {
		vbnn_ibs_user_null(user);
		vbnn_ibs_user_new(user);

		ec_copy(user->R, other.user->R);
		bn_copy(user->s, other.user->s);
	}
	
	~IBC_User() {
		vbnn_ibs_user_free(user);
	}

public:
	vbnn_ibs_user_t user;
};

class ec {
public:
	ec() {
		ec_null(p);
		ec_new(p);
	}

	ec( const ec& other ) {
		ec_null(p);
		ec_new(p);

		ec_copy(p, other.p);
	}

	ec( ec& other ) {
		ec_null(p);
		ec_new(p);

		ec_copy(p, other.p);
	}
	
	~ec() {
		ec_free(p);
	}

public:
	ec_t p;
};

class TA {
public:
	static std::shared_ptr<TA> init();
	static std::shared_ptr<TA> load(const std::vector<uint8_t>& data);

public:
	TA();
	~TA();

	std::vector<uint8_t> save();
	std::vector<uint8_t> getPublicKey();
	IBC_User extractIdentityKey(const std::vector<uint8_t>& id);

public:
	vbnn_ibs_kgc_t kgc_;
};

class Signature {
public:
	Signature() {
		ec_null(R);
		bn_null(z);
		bn_null(h);
		ec_new(R);
		bn_new(z);
		bn_new(h);
	}

	Signature( const Signature& other ) {
		ec_null(R);
		bn_null(z);
		bn_null(h);
		ec_new(R);
		bn_new(z);
		bn_new(h);

		ec_copy(R, other.R);
		bn_copy(z, other.z);
		bn_copy(h, other.h);
	}

	Signature( Signature& other ) {
		ec_null(R);
		bn_null(z);
		bn_null(h);
		ec_new(R);
		bn_new(z);
		bn_new(h);

		ec_copy(R, other.R);
		bn_copy(z, other.z);
		bn_copy(h, other.h);
	}
	
	~Signature() {
		ec_free(R);
		bn_free(z);
		bn_free(h);
	}

	static Signature fromCBORArray(cbor_item_t* item) {
		Signature sig;
		assert(cbor_array_size(item) == 3);
		relic_cbor2ec_compressed(sig.R, cbor_array_get(item, 0));
		relic_cbor2bn(sig.z, cbor_array_get(item, 1));
		relic_cbor2bn(sig.h, cbor_array_get(item, 2));
		return sig;
	}

	cbor_item_t* toCBORArray() {
		cbor_item_t* array = cbor_new_definite_array(3);
		cbor_array_push(array, cbor_move(relic_ec2cbor_compressed(R)));
		cbor_array_push(array, cbor_move(relic_bn2cbor(z)));
		cbor_array_push(array, cbor_move(relic_bn2cbor(h)));
		return array;
	}

public:
	static Signature sign(std::shared_ptr<IBC_User> user, std::vector<uint8_t> &id, std::vector<uint8_t> &data) {
		Signature sig;
		cp_vbnn_ibs_user_sign(
			sig.R, 
			sig.z, 
			sig.h, 
			id.data(), 
			id.size(), 
			data.data(), 
			data.size(), 
			user->user);
		return sig;
	}

	static bool verify(std::vector<uint8_t> &id, std::vector<uint8_t> &data, ec_t mpk, Signature &sig) {
		if (cp_vbnn_ibs_user_verify(sig.R, sig.z, sig.h, id.data(), id.size(), data.data(), data.size(), mpk) == 1) {
			return true;
		}
		else {
			return false;
		}
	}

public:
	ec_t R;
	bn_t z;
	bn_t h;
};