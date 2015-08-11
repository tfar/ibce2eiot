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

#include <cbor.h>
#ifdef __cplusplus
extern "C" {
#endif
	#include <relic.h>
#ifdef __cplusplus
}
#endif

/*
 *  Serialize RELIC data structures as CBOR items.
 */
cbor_item_t* relic_bn2cbor(const bn_t n);
cbor_item_t* relic_fp2cbor(const fp_t n);
cbor_item_t* relic_ec2cbor(const ec_t n);
cbor_item_t* relic_ec2cbor_compressed(const ec_t n);

/*
 *  Parse RELIC data structures from CBOR items.
 */
void relic_cbor2bn(bn_t n, const cbor_item_t* item);
void relic_cbor2fp(fp_t n, const cbor_item_t* item);
void relic_cbor2ec(ec_t n, const cbor_item_t* item);
void relic_cbor2ec_compressed(ec_t, const cbor_item_t* item);