#include "kernel.h"
#include "net/ng_netbase.h"
#include "net/ng_ipv6.h"
#include "net/ng_udp.h"
#include "net/ng_pktdump.h"

void send_udp_packet(ng_ipv6_addr_t addr, uint16_t port, uint8_t* data, size_t length);