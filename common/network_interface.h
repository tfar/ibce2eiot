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

#include <string>
#include <memory>

/*
ULA
fd2d:0388:6a7b:018e:e631:728b:eb82:8005/112 (Example)
fd2d:0388:6a7b:HHHH:HHHH:HHHH:HHHH:NNNN/112
-+-----------+-------------------+----+
 |           |                   |    |
 |           |                   |    +----- Node ID         (8 bit)
 |           |                   +---------- Hash            (64 bit)
 |           +------------------------------ Global prefix   (40 bit)
 *------------------------------------------ ULA prefix      (16 bit)
*/


class NetworkInterface {
public:
	NetworkInterface(const boost::asio::ip::address_v6& prefix);
	~NetworkInterface();

	void configureInterface(const std::string& interface, std::shared_ptr<TA> ta);

	boost::asio::ip::address_v6 getUsedAddress() const;
	std::string getInterfaceName() const;

private:
	std::string interface_;
	boost::asio::ip::address_v6 prefix_;
	boost::asio::ip::address_v6 usedAddress_;
};