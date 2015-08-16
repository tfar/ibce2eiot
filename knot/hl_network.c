#include <stdio.h>
#include <inttypes.h>

#include "kernel.h"
#include "net/ng_ipv6.h"
#include "net/ipv6/addr.h"
#include "net/ng_ipv6/hdr.h"
#include "net/ng_netbase.h"
#include "net/ng_sixlowpan.h"
#include "net/ng_udp.h"
#include "od.h"
#include "ps.h"
#include "sched.h"

#include "hl_network.h"

static ng_netreg_entry_t knot_server_init = {NULL, NG_NETREG_DEMUX_CTX_ALL,
                                   KERNEL_PID_UNDEF};
static ng_netreg_entry_t knot_server_api = {NULL, NG_NETREG_DEMUX_CTX_ALL,
                                   KERNEL_PID_UNDEF};
static ng_netreg_entry_t knot_server_lookup = {NULL, NG_NETREG_DEMUX_CTX_ALL,
                                   KERNEL_PID_UNDEF};

static char knot_stack[512*7 + 512]; // *5 works

extern void knot_handle_dynamic_configuration_reply(const uint8_t* reply, size_t replyLen);
extern void knot_handle_authenticated_query(const ipv6_addr_t* src_addr, const uint8_t* reply, size_t replyLen);
extern void knot_handle_ta_lookup_response(const ipv6_addr_t* src_addr, const uint8_t* reply, size_t replyLen);

static int net_get_udp_payload(ng_pktsnip_t *snip, uint8_t* src_addr, uint8_t* dst_addr, uint16_t *dst_port, uint8_t **buffer, size_t *buffer_size) {
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
        else if (snip->type == NG_NETTYPE_UDP) {
            headers++;
            ng_udp_hdr_t* udp_head = snip->data;
            *dst_port = byteorder_ntohs(udp_head->dst_port);
        }
        else if (snip->type == NG_NETTYPE_IPV6) {
            headers++;
            ng_ipv6_hdr_t* ipv6_head = snip->data;
            memcpy(src_addr, &ipv6_head->src, 16);
            memcpy(dst_addr, &ipv6_head->dst, 16);
        }
        //_dump_snip(snip);
        ++snips;
        size += snip->size;
        snip = snip->next;
    }

    ng_pktbuf_release(snip);
    return headers;
}

static void *knot_eventloop(void *arg) {
    (void)arg;
    msg_t msg;
    msg_t msg_queue[10];

    /* setup the message queue */
    msg_init_queue(msg_queue, 10);

    while (1) {
        msg_receive(&msg);

        switch (msg.type) {
            case NG_NETAPI_MSG_TYPE_RCV:
                puts("received message");
                ipv6_addr_t src_addr;
                ipv6_addr_t dst_addr;
                uint16_t port = 0;
                uint8_t *payload = NULL;
                size_t pLen;
                int success = net_get_udp_payload((ng_pktsnip_t *)msg.content.ptr, (void*)&src_addr, (void*)&dst_addr, &port, &payload, &pLen);
                if (success == 3) {
                    if (port == 4223) {
                        printf("Received dynamic configuration request\n");
                        knot_handle_dynamic_configuration_reply(payload, pLen);
                    }
                    else if (port == 4222) {
                        printf("Received authenticated query request\n");
                        knot_handle_authenticated_query(&src_addr, payload, pLen);
                    }
                    else if (port == 4224) {
                        printf("Received TA lookup response\n");
                        knot_handle_ta_lookup_response(&src_addr, payload, pLen);
                    }
                    else {
                        printf("Unsupported port: %d\n", port);
                    }
                }
                else {
                    printf("Not an UDP packet.\n");
                }
                if (payload != NULL) {
                    free(payload);
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

void knot_start_server(char *port_str) {
    uint16_t port;

    /* check if knot_server is already running */
    if (knot_server_init.pid != KERNEL_PID_UNDEF) {
        printf("Error: knot_server already running on port %" PRIu32 "\n",
                knot_server_init.demux_ctx);
        return;
    }

    /* parse port */
    port = (uint16_t)atoi(port_str);
    if (port == 0) {
        puts("Error: invalid port specified");
        return;
    }

    /* start knot_server (which means registering pktdump for the chosen port) */
    knot_server_init.pid = thread_create(knot_stack, sizeof(knot_stack), THREAD_PRIORITY_MAIN + 1, 
                                CREATE_STACKTEST /* | CREATE_SLEEPING */, knot_eventloop, NULL, "UDP receiver");
    // register for dynamic configuration reply
    knot_server_init.demux_ctx = 4223;
    ng_netreg_register(NG_NETTYPE_UDP, &knot_server_init);

    // register for signed messages
    knot_server_api.pid = knot_server_init.pid;
    knot_server_api.demux_ctx = 4222;
    ng_netreg_register(NG_NETTYPE_UDP, &knot_server_api);

    knot_server_lookup.pid = knot_server_init.pid;
    knot_server_lookup.demux_ctx = 4224;
    ng_netreg_register(NG_NETTYPE_UDP, &knot_server_lookup);

    printf("Success: started UDP server\n");
}

void knot_send_udp_packet(ipv6_addr_t addr, uint16_t port, uint8_t* data, size_t length) {
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
