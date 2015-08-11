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