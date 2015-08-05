#include <stdio.h>
#include <inttypes.h>

#include "kernel.h"
#include "net/ng_netbase.h"
#include "net/ng_ipv6.h"
#include "net/ng_udp.h"
#include "net/ng_pktdump.h"

void send_udp_packet(ng_ipv6_addr_t addr, uint16_t port, uint8_t* data, size_t length) {
    ng_pktsnip_t *payload, *udp, *ip;
    ng_netreg_entry_t *sendto;

    /* allocate payload */
    payload = ng_pktbuf_add(NULL, data, length, NG_NETTYPE_UNDEF);
    if (payload == NULL) {
        puts("Error: unable to copy data to packet buffer");
        return;
    }

    /* allocate UDP header, set source port := destination port */
    udp = ng_udp_hdr_build(payload, (uint8_t*)&port, 2, (uint8_t*)&port, 2);
    if (udp == NULL) {
        puts("Error: unable to allocate UDP header");
        ng_pktbuf_release(payload);
        return;
    }

    /* allocate IPv6 header */
    ip = ng_ipv6_hdr_build(udp, NULL, 0, (uint8_t *)&addr, sizeof(addr));
    if (ip == NULL) {
        puts("Error: unable to allocate IPv6 header");
        ng_pktbuf_release(udp);
        return;
    }
    
    /* send packet */
    sendto = ng_netreg_lookup(NG_NETTYPE_UDP, NG_NETREG_DEMUX_CTX_ALL);
    if (sendto == NULL) {
        puts("Error: unable to locate UDP thread");
        ng_pktbuf_release(ip);
        return;
    }
    ng_pktbuf_hold(ip, ng_netreg_num(NG_NETTYPE_UDP,
                                     NG_NETREG_DEMUX_CTX_ALL) - 1);
    while (sendto != NULL) {
        ng_netapi_send(sendto->pid, ip);
        sendto = ng_netreg_getnext(sendto);
    }
}
