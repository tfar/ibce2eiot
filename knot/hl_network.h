#pragma once

#include "kernel.h"
#include "net/ng_netbase.h"
#include "net/ng_ipv6.h"
#include "net/ipv6/addr.h"
#include "net/ng_udp.h"

void knot_send_udp_packet(ipv6_addr_t addr, uint16_t port, uint8_t* data, size_t length);
void knot_start_server(void);