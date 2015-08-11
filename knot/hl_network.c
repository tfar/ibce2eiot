#include <stdio.h>
#include <inttypes.h>

#include "kernel.h"
#include "net/ng_ipv6.h"
#include "net/ng_ipv6/addr.h"
#include "net/ng_ipv6/hdr.h"
#include "net/ng_netbase.h"
#include "net/ng_pktdump.h"
#include "net/ng_sixlowpan.h"
#include "net/ng_udp.h"
#include "od.h"

#include "hl_network.h"

static ng_netreg_entry_t server = {NULL, NG_NETREG_DEMUX_CTX_ALL,
                                   KERNEL_PID_UNDEF};

static char _stack[1024];


#if 0
static void _dump_snip(ng_pktsnip_t *pkt)
{
    switch (pkt->type) {
        case NG_NETTYPE_UNDEF:
            printf("NETTYPE_UNDEF (%i)\n", pkt->type);
            od_hex_dump(pkt->data, pkt->size, OD_WIDTH_DEFAULT);
            break;
#ifdef MODULE_NG_NETIF
        case NG_NETTYPE_NETIF:
            printf("NETTYPE_NETIF (%i)\n", pkt->type);
            ng_netif_hdr_print(pkt->data);
            break;
#endif
#ifdef MODULE_NG_SIXLOWPAN
        case NG_NETTYPE_SIXLOWPAN:
            printf("NETTYPE_SIXLOWPAN (%i)\n", pkt->type);
            ng_sixlowpan_print(pkt->data, pkt->size);
            break;
#endif
#ifdef MODULE_NG_IPV6
        case NG_NETTYPE_IPV6:
            printf("NETTYPE_IPV6 (%i)\n", pkt->type);
            ng_ipv6_hdr_print(pkt->data);
            break;
#endif
#ifdef MODULE_NG_ICMPV6
        case NG_NETTYPE_ICMPV6:
            printf("NETTYPE_ICMPV6 (%i)\n", pkt->type);
            break;
#endif
#ifdef MODULE_NG_TCP
        case NG_NETTYPE_TCP:
            printf("NETTYPE_TCP (%i)\n", pkt->type);
            break;
#endif
#ifdef MODULE_NG_UDP
        case NG_NETTYPE_UDP:
            printf("NETTYPE_UDP (%i)\n", pkt->type);
            ng_udp_hdr_print(pkt->data);
            break;
#endif
#ifdef TEST_SUITES
        case NG_NETTYPE_TEST:
            printf("NETTYPE_TEST (%i)\n", pkt->type);
            od_hex_dump(pkt->data, pkt->size, OD_WIDTH_DEFAULT);
            break;
#endif
        default:
            printf("NETTYPE_UNKNOWN (%i)\n", pkt->type);
            od_hex_dump(pkt->data, pkt->size, OD_WIDTH_DEFAULT);
            break;
    }
}

static void _dump(ng_pktsnip_t *pkt)
{
    int snips = 0;
    int size = 0;
    ng_pktsnip_t *snip = pkt;

    while (snip != NULL) {
        printf("~~ SNIP %2i - size: %3u byte, type: ", snips,
               (unsigned int)snip->size);
        _dump_snip(snip);
        ++snips;
        size += snip->size;
        snip = snip->next;
    }

    printf("~~ PKT    - %2i snips, total size: %3i byte\n", snips, size);
    ng_pktbuf_release(pkt);
}
#endif

static int net_get_udp_payload(ng_pktsnip_t *snip, uint8_t* src_addr, uint8_t **buffer, size_t *buffer_size) {
    int snips = 0;
    int size = 0;

    int headers = 0;
    while (snip != NULL) {
        if (snip->type == NG_NETTYPE_UNDEF) {
            headers++;
            *buffer = malloc(snip->size);
            *buffer_size = snip->size;
            memcpy(*buffer, snip->data, *buffer_size);
        }
        else if (snip->type == NG_NETTYPE_IPV6) {
            headers++;
            ng_ipv6_hdr_t* ipv6_head = snip->data;
            memcpy(src_addr, &ipv6_head->src, 16);
        }
        //_dump_snip(snip);
        ++snips;
        size += snip->size;
        snip = snip->next;
    }

    ng_pktbuf_release(snip);
    return headers;
}

static void *_eventloop(void *arg) {
    (void)arg;
    msg_t msg;
    msg_t msg_queue[NG_PKTDUMP_MSG_QUEUE_SIZE];

    /* setup the message queue */
    msg_init_queue(msg_queue, NG_PKTDUMP_MSG_QUEUE_SIZE);

    while (1) {
        msg_receive(&msg);
        puts("got message");

        switch (msg.type) {
            case NG_NETAPI_MSG_TYPE_RCV:
                puts("received message");
                uint8_t src_addr[16];
                uint8_t *payload = NULL;
                size_t pLen;
                int success = net_get_udp_payload((ng_pktsnip_t *)msg.content.ptr, src_addr, &payload, &pLen);
                printf("(success: %d) source address: ", success);
                for (int n = 0; n < 16; n++) {
                    printf("%02x:", src_addr[n]);
                }
                printf("\n");
                if (payload) {
                    for (int n = 0; n < pLen; n++) {
                        printf("%02x", payload[n]);
                    }
                    free(payload);
                    printf("\n");
                }
                break;
            default:
                puts("default");
                break;
        }
    }

    /* never reached */
    return NULL;
}


void start_server(char *port_str) {
    uint16_t port;

    /* check if server is already running */
    if (server.pid != KERNEL_PID_UNDEF) {
        printf("Error: server already running on port %" PRIu32 "\n",
                server.demux_ctx);
        return;
    }

    /* parse port */
    port = (uint16_t)atoi(port_str);
    if (port == 0) {
        puts("Error: invalid port specified");
        return;
    }
    /* start server (which means registering pktdump for the chosen port) */
    server.pid = thread_create(_stack, sizeof(_stack), THREAD_PRIORITY_MAIN - 4, 
                                CREATE_STACKTEST, _eventloop, NULL, "UDP receiver");
    server.demux_ctx = 4223;
    ng_netreg_register(NG_NETTYPE_UDP, &server);
    printf("Success: started UDP server\n");
}

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
