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

#include <vector>
#include <array>
#include <tuple>

extern "C" {
	#include <norx.h>
}

class NORX {
public:
	static std::vector<uint8_t> encrypt(
		const std::vector<uint8_t> header, 
		const std::vector<uint8_t> plain, 
		const std::vector<uint8_t> footer,
		const std::array<uint8_t, 16>& nonce,
		const std::array<uint8_t, 16>& key) {
		std::vector<uint8_t> cipher;
		cipher.resize(plain.size() + 128);

		unsigned char* c = cipher.data();
		size_t cLen = cipher.size();
		const unsigned char* h = header.empty() ? 0 : header.data();
		size_t hLen = header.size();
		const unsigned char* p = plain.data();
		size_t pLen = plain.size();
		const unsigned char* t = footer.empty() ? 0 : footer.data();
		size_t tLen = footer.size();

		norx_aead_encrypt(c, &cLen, h, hLen, p, pLen, t, tLen, nonce.data(), key.data());
		cipher.resize(cLen);
		return cipher;
	}

	static std::tuple<bool, std::vector<uint8_t> > decrypt(
		const std::vector<uint8_t> header, 
		const std::vector<uint8_t> cipher, 
		const std::vector<uint8_t> footer,
		const std::array<uint8_t, 16>& nonce,
		const std::array<uint8_t, 16>& key) {
		std::vector<uint8_t> plain;
		plain.resize(cipher.size());

		unsigned char* p = plain.data();
		size_t pLen = plain.size();
		const unsigned char* h = header.empty() ? 0 : header.data();
		size_t hLen = header.size();
		const unsigned char* c = cipher.data();
		size_t cLen = cipher.size();
		const unsigned char* t = footer.empty() ? 0 : footer.data();
		size_t tLen = footer.size();

		std::tuple<bool, std::vector<uint8_t> > retVal;
		std::get<0>(retVal) = false;
		if (norx_aead_decrypt(p, &pLen, h, hLen, c, cLen, t, tLen, nonce.data(), key.data()) == 0) {
			plain.resize(pLen);
			std::get<1>(retVal) = plain;
			std::get<0>(retVal) = true;
		}
		return retVal;
	}
};