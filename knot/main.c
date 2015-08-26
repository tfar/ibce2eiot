#include <stdio.h>

#include "board_uart0.h"
#include "cbor.h"
#include "net/ng_netapi.h"
#include "net/ng_netif.h"
#include "net/netopt.h"
#include "posix_io.h"
#include "unistd.h"
#include "ps.h"
#include "board.h"

#include <relic.h>
#include <norx.h>

#include <malloc.h>

#ifndef NO_KNOT_PRINT
#define KNOT_PRINT(...) printf(__VA_ARGS__)
#else
#define KNOT_PRINT(...) do {} while (0)
#endif

#include "relic_cbor.h"

#include "hl_network.h"

extern void knot_send(char *addr_str, char *port_str, char *data);

const uint8_t knot_confRequestKey[16] = {0x82, 0x02, 0x1a, 0xb1, 0x47, 0xd8, 0xbb, 0x75, 
                                    0x91, 0x17, 0x4d, 0x9c, 0x81, 0x74, 0x3e, 0x3b};
const uint8_t knot_confResponseKey[16] ={0xbe, 0x87, 0x7c, 0x23, 0xf0, 0x6c, 0x59, 0x69,
                                    0x92, 0xda, 0xe9, 0xd1, 0xf2, 0xf9, 0x36, 0x7c};

uint8_t knot_configNonce[16];
uint8_t own_address[16];

static ec_t knot_localTA;
static vbnn_ibs_user_t knot_ownUser;

static ec_t knot_remoteTA_key[1];
static uint8_t knot_remoteTA_prefix[1][14] = {{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}};

void* knot_unauthenticatedLastMessage = 0;
size_t knot_unauthenticatedLastMessageLen = 0;
ipv6_addr_t knot_unauthenticatedLastMessageAddr;

#ifndef NO_KNOT_PRINT
static char* knot_addr2s(const ipv6_addr_t* addr) {
    static char addrStr[40];
    ipv6_addr_to_str(addrStr, addr, 40);
    return addrStr;
}
#endif
#if 0
  size_t arena;    /* total space allocated from system */
  size_t ordblks;  /* number of non-inuse chunks */
  size_t hblks;    /* number of mmapped regions */
  size_t hblkhd;   /* total space in mmapped regions */
  size_t uordblks; /* total allocated space */
  size_t fordblks; /* total non-inuse space */
  size_t keepcost; /* top-most, releasable (via malloc_trim) space */
#endif

void knot_print_heap_stats(void) {
    KNOT_PRINT("heap stats:     arena: %d, ordblks: %d, hblks: %d, hblkhd: %d, uordblks: %d, fordblks: %d\n", 
        mallinfo().arena, 
        mallinfo().ordblks, 
        mallinfo().hblks,
        mallinfo().hblkhd,
        mallinfo().uordblks, 
        mallinfo().fordblks);
}

int knot_verify_message(ipv6_addr_t *src_addr, uint8_t *data, size_t dataLen, char *cmd);
void knot_send_authenticated_reply(ipv6_addr_t* target_address);

void knot_request_network_and_identity_from_gateway(void) {
    uint8_t cborBuffer[50];
    cbor_stream_t stream;
    KNOT_PRINT("knot_request_network_and_identity_from_gateway: begin\n");
    // generate nonce
    rand_bytes(knot_configNonce, 16);

    KNOT_PRINT("Begin CBOR encoding.\n");
    cbor_init(&stream, cborBuffer, 50);
    cbor_serialize_unicode_string(&stream, "REQ");
    KNOT_PRINT("End CBOR encoding.\n");
    // compute request ciphertext
    uint8_t* requestCiphertext = malloc(stream.pos);
    size_t requestCiphertextLen = 0;
    const unsigned char* header = 0;
    size_t headerLen = 0;
    const unsigned char* plaintext = stream.data;
    size_t plaintextLen = stream.pos;
    const unsigned char* trailer = 0;
    size_t trailerLen = 0;

    KNOT_PRINT("Begin NORX encryption.\n");
    norx_aead_encrypt(requestCiphertext, &requestCiphertextLen, header, headerLen, 
        plaintext, plaintextLen, trailer, trailerLen, knot_configNonce, knot_confRequestKey);
    KNOT_PRINT("End NORX encryption.\n");
    cbor_clear(&stream);

    KNOT_PRINT("Begin CBOR encoding.\n");
    // compute request message
    cbor_serialize_array(&stream, 2);
    cbor_serialize_byte_stringl(&stream, (char*)knot_configNonce, 16);
    cbor_serialize_byte_stringl(&stream, (char*)requestCiphertext, requestCiphertextLen);
    KNOT_PRINT("End CBOR encoding.\n");

    ipv6_addr_t toAddress;
    ipv6_addr_from_str(&toAddress, "ff02::0e2e:0ecc");

    knot_send_udp_packet(toAddress, 4223, stream.data, stream.pos);

    free(requestCiphertext);
    requestCiphertext = 0;
    KNOT_PRINT("knot_request_network_and_identity_from_gateway: end\n");
}

int knot_set_address(const cbor_stream_t *stream, size_t offset) {
    uint8_t value[16];
    int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
    
    // set IPv6 address to value
    ipv6_addr_t addr;
    memcpy(&addr.u8, value, 16);
    memcpy(own_address, value, 16);


    if (ng_ipv6_netif_add_addr(7, &addr, 112, NG_IPV6_NETIF_ADDR_FLAGS_UNICAST) != NULL) {
        KNOT_PRINT("Successfully set IPv6 address to %s\n", knot_addr2s(&addr));
    }
    else {
        KNOT_PRINT("Failed to set IPv6 address!\n");
    }


    return ret;
}

void knot_handle_dynamic_configuration_reply(const uint8_t* reply, size_t replyLen) {
    KNOT_PRINT("Attempt do decrypt dynamic configuration response.\n");
    uint8_t* plaintext = malloc(replyLen);
    size_t plaintextLen = replyLen;

    const uint8_t* header = 0;
    size_t headerLen = 0;
    const uint8_t* trailer = 0;
    size_t trailerLen = 0;
    KNOT_PRINT("Begin NORX decryption\n");
    int result = norx_aead_decrypt(plaintext, &plaintextLen, header, headerLen,
            reply, replyLen, trailer, trailerLen, knot_configNonce, knot_confResponseKey);
    KNOT_PRINT("End NORX decryption\n");
    if (result == 0) {
        KNOT_PRINT("Begin CBOR decoding\n");
        cbor_stream_t stream;
        cbor_init(&stream, plaintext, plaintextLen);

        size_t mapLength = 0;
        size_t offset = cbor_deserialize_map(&stream, 0, &mapLength);
        
        for (int mapIndex = 0; mapIndex < mapLength; mapIndex++) {
            char key[10];
            offset += cbor_deserialize_unicode_string(&stream, offset, key, 10);

            if (strncmp("mpk", key, 3) == 0) {
                offset += relic_cbor2ec_compressed(knot_localTA, &stream, offset);
            }
            else if (strncmp("id", key, 2) == 0) {
                offset += knot_set_address(&stream, offset);
            }
            else if (strncmp("key", key, 3) == 0) {
                size_t length;
                offset += cbor_deserialize_array(&stream, offset, &length);
                assert(length == 2);
                offset += relic_cbor2ec_compressed(knot_ownUser->R, &stream, offset);
                offset += relic_cbor2bn(knot_ownUser->s, &stream, offset);
            }
        }
        KNOT_PRINT("End CBOR decoding\n");
        KNOT_PRINT("Dynamic configuration completed.\n");
    }
    else {
        KNOT_PRINT("Decryption of dynamic configuration request failed.\n");
    }
    knot_print_heap_stats();
}

void knot_TA_lookup_request_send(const ipv6_addr_t* forAddress) {
    ipv6_addr_t lookupAddress;
    memcpy(&lookupAddress, forAddress, sizeof(ipv6_addr_t));
    lookupAddress.u8[14] = 0x0;
    lookupAddress.u8[15] = 0x1;

    uint8_t cborBuffer[10];
    cbor_stream_t stream;


    cbor_init(&stream, cborBuffer, 10);
    cbor_serialize_unicode_string(&stream, "TAL");

    knot_send_udp_packet(lookupAddress, 4224, stream.data, stream.pos);

    cbor_clear(&stream);

    KNOT_PRINT("Send TA lookup request to %s.\n", knot_addr2s(&lookupAddress));
}

void knot_clear_last_message(void) {
    if (knot_unauthenticatedLastMessage) {
        free(knot_unauthenticatedLastMessage);
        knot_unauthenticatedLastMessageLen = 0;
        memset(&knot_unauthenticatedLastMessageAddr, 0, sizeof(knot_unauthenticatedLastMessageAddr));
    }
}

void knot_handle_authenticated_query(ipv6_addr_t* src_addr, uint8_t* reply, size_t replyLen) {
    KNOT_PRINT("Begin of knot_handle_authenticated_query for %s\n", knot_addr2s(src_addr));
    if (knot_remoteTA_prefix[0][0] == 0) {
        KNOT_PRINT("No remote TA available yet.\n");
        KNOT_PRINT("Cache current message for later\n");
        knot_clear_last_message();
        knot_unauthenticatedLastMessage = malloc(replyLen);
        knot_unauthenticatedLastMessageLen = replyLen;
        memcpy(knot_unauthenticatedLastMessage, reply, knot_unauthenticatedLastMessageLen);
        memcpy(&knot_unauthenticatedLastMessageAddr, src_addr, sizeof(ipv6_addr_t));
        knot_TA_lookup_request_send(src_addr);
    }
    else {
        KNOT_PRINT("Remote TA key available, checking prefix.\n");
        if (memcmp(src_addr, knot_remoteTA_prefix[0], 14) == 0) {
            KNOT_PRINT("Authenticate message from %s\n", knot_addr2s(src_addr));
            char cmd[10];
            int validSig = knot_verify_message(src_addr, reply, replyLen, cmd);
            if (validSig) {
                if (strncmp("rnd", cmd, 3) == 0) {
                    knot_send_authenticated_reply(src_addr);
                }
            }
        }
    }

    KNOT_PRINT("End of knot_handle_authenticated_query for %s\n", knot_addr2s(src_addr));
}

int knot_verify_message(ipv6_addr_t *src_addr, uint8_t *data, size_t dataLen, char *cmd) {
    KNOT_PRINT("Begin of knot_verify_message for %s\n", knot_addr2s(src_addr));
    knot_print_heap_stats();
    KNOT_PRINT("Begin CBOR decoding.\n");
    cbor_stream_t stream;
    cbor_init(&stream, data, dataLen);

    int result = 0;
    size_t mapLength = 0;
    size_t offset = cbor_deserialize_map(&stream, 0, &mapLength);
    assert(mapLength == 2);

    char* message = NULL;

    ec_t R;
    bn_t z;
    bn_t h;

    ec_null(R); ec_new(R);
    bn_null(z); bn_new(z);
    bn_null(h); bn_new(h);

    for (int mapIndex = 0; mapIndex < mapLength; mapIndex++) {
        char key[4];
        char tmpMessage[10];
        memset(key, 0, sizeof(key));
        offset += cbor_deserialize_unicode_string(&stream, offset, key, 10);

        if (strncmp("msg", key, 3) == 0) {
            memset(tmpMessage, 0, sizeof(tmpMessage));
            offset += cbor_deserialize_byte_string(&stream, offset, tmpMessage, sizeof(tmpMessage));
            message = malloc(strlen(tmpMessage + 1));
            strncpy(message, tmpMessage, 10);
        }
        else if (strncmp("sig", key, 3) == 0) {
            size_t length;
            offset += cbor_deserialize_array(&stream, offset, &length);
            assert(length == 3);
            offset += relic_cbor2ec_compressed(R, &stream, offset);
            offset += relic_cbor2bn(z, &stream, offset);
            offset += relic_cbor2bn(h, &stream, offset);
        }
    }
    KNOT_PRINT("End CBOR decoding.\n");

    KNOT_PRINT("Begin verifying message.\n");
    LED_TOGGLE;
    if (cp_vbnn_ibs_user_verify(R, z, h, (uint8_t*)src_addr, 16, (uint8_t*)message, strlen(message), knot_remoteTA_key[0]) != 0) {
        KNOT_PRINT("Signature is valid.\n");
        strncpy(cmd, message, 10);
        result = 1;
    }
    else {
        result = 0;
        KNOT_PRINT("Signature is invalid.\n");
    }
    LED_TOGGLE;
    KNOT_PRINT("End verifying message.\n");
    free(message);
    ec_free(R); bn_free(z); bn_free(h);
    knot_print_heap_stats();
    KNOT_PRINT("End of knot_verify_message for %s\n", knot_addr2s(src_addr));
    return result;
}

void knot_send_authenticated_reply(ipv6_addr_t* target_address) {
    KNOT_PRINT("Begin of knot_send_authenticated_reply for %s\n", knot_addr2s(target_address));
    knot_print_heap_stats();
    uint8_t replyBuffer[200];
    uint8_t reply[10];
    rand_bytes(reply, 10);
    KNOT_PRINT("Reply data: ");
    for (int n = 0; n < 10; n++) KNOT_PRINT("%02x", reply[n]);
    KNOT_PRINT("\n");
    KNOT_PRINT("Begin signing data.\n");
    ec_t R;
    bn_t z;
    bn_t h;

    ec_null(R); ec_new(R);
    bn_null(z); bn_new(z);
    bn_null(h); bn_new(h);

    LED_TOGGLE;
    cp_vbnn_ibs_user_sign(R, z, h, own_address, 16, (uint8_t*)reply, sizeof(reply), knot_ownUser);
    LED_TOGGLE;
    KNOT_PRINT("End signing data.\n");

    KNOT_PRINT("Begin CBOR encoding.\n");
    cbor_stream_t stream;
    cbor_init(&stream, replyBuffer, sizeof(replyBuffer));
    cbor_serialize_map(&stream, 2);
    cbor_serialize_unicode_string(&stream, "msg");
    cbor_serialize_byte_stringl(&stream, (char*)reply, sizeof(reply));
    cbor_serialize_unicode_string(&stream, "sig");
    cbor_serialize_array(&stream, 3);
    relic_ec2cbor_compressed(&stream, R);
    relic_bn2cbor(&stream, z);
    relic_bn2cbor(&stream, h);
    KNOT_PRINT("End CBOR encoding.\n");

    ec_free(R); bn_free(z); bn_free(h);

    knot_send_udp_packet(*target_address, 4222, stream.data, stream.pos);

    knot_print_heap_stats();
    KNOT_PRINT("End of knot_send_authenticated_reply for %s\n", knot_addr2s(target_address));
}

void knot_handle_ta_lookup_response(ipv6_addr_t* src_addr, uint8_t* reply, size_t replyLen) {
    KNOT_PRINT("Begin of knot_handle_ta_lookup_response for %s\n", knot_addr2s(src_addr));
    cbor_stream_t stream;

    KNOT_PRINT("Begin CBOR decoding.\n");
    cbor_init(&stream, (uint8_t*)reply, replyLen);
    char prefixPlustaPK[6 + 35];
    
    //cbor_deserialize_byte_string(&stream, 0, taPublicKeyBin, sizeof(taPublicKeyBin));
    KNOT_PRINT("End CBOR decoding.\n");

    KNOT_PRINT("Begin verifying TA public key agianst embedded hash.\n");
    /* 6 bytes global prefix */
    memcpy(prefixPlustaPK, src_addr, 6);
    /* FP_BYTES + 1 bytes TA public key */
    memcpy(prefixPlustaPK + 6, reply, replyLen);

    uint8_t hash[MD_LEN];
    md_map(hash, (uint8_t*)prefixPlustaPK, sizeof(prefixPlustaPK));
    if (util_cmp_const(((uint8_t*)src_addr) + 6, hash, 8) == CMP_EQ) {
        KNOT_PRINT("TA public key verification successful.\n");
        
        KNOT_PRINT("Store prefix/TA public key in cache.\n");
        memcpy(knot_remoteTA_prefix[0], src_addr, 14);
        relic_cbor2ec_compressed(knot_remoteTA_key[0], &stream, 0);
        KNOT_PRINT("End verifying TA public key agianst embedded hash.\n");

        if (knot_unauthenticatedLastMessage) {
            KNOT_PRINT("Authenticate last unauthenticated message from %s\n", knot_addr2s(&knot_unauthenticatedLastMessageAddr));
            char cmd[10];
            int validSig = knot_verify_message(&knot_unauthenticatedLastMessageAddr, knot_unauthenticatedLastMessage, knot_unauthenticatedLastMessageLen, cmd);
            if (validSig) {
                if (strncmp("rnd", cmd, 3) == 0) {
                    knot_send_authenticated_reply(&knot_unauthenticatedLastMessageAddr);
                    knot_clear_last_message();
                }
            }
        }
    }
    else {
        KNOT_PRINT("TA public key verification failed.\n");
        KNOT_PRINT("End verifying TA public key agianst embedded hash.\n");
    }

    KNOT_PRINT("End of knot_handle_ta_lookup_response for %s\n", knot_addr2s(src_addr));
}

int main(void)
{
    KNOT_PRINT("RIOT IBC E2E Authentication for IoT Application\n");
    KNOT_PRINT("START\n");
    
    /* set 802.15.4 channel to 12 */
    //net_if_set_channel(7, 12);
    uint16_t channel = 25;
    ng_netapi_set(7, NETOPT_CHANNEL, 0, &channel, sizeof(uint16_t));
    KNOT_PRINT("Set channel to 25");

    uint16_t retrans = 7;
    ng_netapi_set(7, NETOPT_RETRANS, 0, &retrans, sizeof(uint16_t));

    KNOT_PRINT("retrans: %d\n", retrans);

    knot_print_heap_stats();
    KNOT_PRINT("Initialize RELIC...\n");
    core_init();
    ec_param_set_any();

    ec_null(knot_localTA);
    ec_new(knot_localTA);

    vbnn_ibs_user_null(knot_ownUser);
    vbnn_ibs_user_new(knot_ownUser);
#ifndef NO_KNOT_PRINT
    conf_print();
#endif
    KNOT_PRINT("RELIC initialized!\n");


    // initiate dynamic initialization
    KNOT_PRINT("Initiate dynamic device initialization\n");
    knot_start_server();
    knot_request_network_and_identity_from_gateway();
    
    posix_open(uart0_handler_pid, 0);

    for(;;) {
        sleep(30);
        KNOT_PRINT(".\n");
    }

    vbnn_ibs_user_free(knot_ownUser);
    ec_free(knot_localTA);

    core_clean();

    /* should be never reached */
    return 0;
}
