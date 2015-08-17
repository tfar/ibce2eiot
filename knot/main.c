#include <stdio.h>

#include "board_uart0.h"
#include "cbor.h"
#include "net/ng_netapi.h"
#include "net/ng_netif.h"
#include "net/netopt.h"
#include "posix_io.h"
#include "unistd.h"
#include "ps.h"

#include <relic.h>
#include <norx.h>

#include <norx.c>

#include "relic_cbor.h"

#include "hl_network.h"

extern void knot_send(char *addr_str, char *port_str, char *data);

const uint8_t knot_confRequestKey[16] = {0x82, 0x02, 0x1a, 0xb1, 0x47, 0xd8, 0xbb, 0x75, 
                                    0x91, 0x17, 0x4d, 0x9c, 0x81, 0x74, 0x3e, 0x3b};
const uint8_t knot_confResponseKey[16] ={0xbe, 0x87, 0x7c, 0x23, 0xf0, 0x6c, 0x59, 0x69,
                                    0x92, 0xda, 0xe9, 0xd1, 0xf2, 0xf9, 0x36, 0x7c};

uint8_t knot_configNonce[16];

static ec_t knot_localTA;
static vbnn_ibs_user_t knot_ownUser;

static ec_t knot_remoteTA_key[1];
static uint8_t knot_remoteTA_prefix[1][14] = {{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}};

void* knot_unauthenticatedLastMessage = 0;
size_t knot_unauthenticatedLastMessageLen = 0;
ipv6_addr_t knot_unauthenticatedLastMessageAddr;

static char* knot_addr2s(const ipv6_addr_t* addr) {
    static char addrStr[40];
    ipv6_addr_to_str(addrStr, addr, 40);
    return addrStr;
}

int knot_verify_message(ipv6_addr_t *src_addr, uint8_t *data, size_t dataLen, char *cmd);
void knot_send_authenticated_reply(ipv6_addr_t* target_address);

void knot_request_network_and_identity_from_gateway(void) {
    uint8_t cborBuffer[50];
    cbor_stream_t stream;
    puts("knot_request_network_and_identity_from_gateway: begin");
    // generate nonce
    rand_bytes(knot_configNonce, 16);

    cbor_init(&stream, cborBuffer, 50);
    cbor_serialize_unicode_string(&stream, "REQ");

    // compute request ciphertext
    uint8_t* requestCiphertext = malloc(stream.pos);
    size_t requestCiphertextLen = 0;
    const unsigned char* header = 0;
    size_t headerLen = 0;
    const unsigned char* plaintext = stream.data;
    size_t plaintextLen = stream.pos;
    const unsigned char* trailer = 0;
    size_t trailerLen = 0;

    norx_aead_encrypt(requestCiphertext, &requestCiphertextLen, header, headerLen, 
        plaintext, plaintextLen, trailer, trailerLen, knot_configNonce, knot_confRequestKey);
    //send("ff02::0e2e:0ecc", "20000", "Hello World!");

    cbor_clear(&stream);

    // compute request message
    cbor_serialize_array(&stream, 2);
    cbor_serialize_byte_stringl(&stream, (char*)knot_configNonce, 16);
    cbor_serialize_byte_stringl(&stream, (char*)requestCiphertext, requestCiphertextLen);

    ipv6_addr_t toAddress;
    ipv6_addr_from_str(&toAddress, "ff02::0e2e:0ecc");

    knot_send_udp_packet(toAddress, 4223, stream.data, stream.pos);

    free(requestCiphertext);
    requestCiphertext = 0;
    puts("knot_request_network_and_identity_from_gateway: end");
}

int knot_set_address(const cbor_stream_t *stream, size_t offset) {
    uint8_t value[16];
    int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
    
    // set IPv6 address to value
    ipv6_addr_t addr;
    memcpy(&addr.u8, value, 16);


    if (ng_ipv6_netif_add_addr(7, &addr, 112, NG_IPV6_NETIF_ADDR_FLAGS_UNICAST) != NULL) {
        printf("Successfully set IPv6 address to %s\n", knot_addr2s(&addr));
    }
    else {
        printf("Failed to set IPv6 address!\n");
    }


    return ret;
}

void knot_handle_dynamic_configuration_reply(const uint8_t* reply, size_t replyLen) {
    puts("Attempt do decrypt dynamic configuration response.");
    printf("Attempt to allocate %d bytes.\n", replyLen);
    uint8_t* plaintext = malloc(replyLen);
    size_t plaintextLen = replyLen;

    const uint8_t* header = 0;
    size_t headerLen = 0;
    const uint8_t* trailer = 0;
    size_t trailerLen = 0;
    int result = norx_aead_decrypt(plaintext, &plaintextLen, header, headerLen,
            reply, replyLen, trailer, trailerLen, knot_configNonce, knot_confResponseKey);

    if (result == 0) {
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
        printf("Dynamic configuration completed.\n");
    }
    else {
        puts("Decryption of dynamic configuration request failed.");
    }
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

    printf("Send TA lookup request to %s.\n", knot_addr2s(&lookupAddress));
}

void knot_clear_last_message(void) {
    if (knot_unauthenticatedLastMessage) {
        free(knot_unauthenticatedLastMessage);
        knot_unauthenticatedLastMessageLen = 0;
        memset(&knot_unauthenticatedLastMessageAddr, 0, sizeof(knot_unauthenticatedLastMessageAddr));
    }
}

void knot_handle_authenticated_query(ipv6_addr_t* src_addr, uint8_t* reply, size_t replyLen) {
    printf("Begin of knot_handle_authenticated_query for %s\n", knot_addr2s(src_addr));
    if (knot_remoteTA_prefix[0][0] == 0) {
        printf("No remote TA available yet.\n");
        printf("Cache current message for later\n");
        knot_clear_last_message();
        knot_unauthenticatedLastMessage = malloc(replyLen);
        knot_unauthenticatedLastMessageLen = replyLen;
        memcpy(knot_unauthenticatedLastMessage, reply, knot_unauthenticatedLastMessageLen);
        memcpy(&knot_unauthenticatedLastMessageAddr, src_addr, sizeof(ipv6_addr_t));
        knot_TA_lookup_request_send(src_addr);
    }
    else {
        printf("Remote TA key available, checking prefix.\n");
        if (memcmp(src_addr, knot_remoteTA_prefix[0], 14) == 0) {
            printf("Authenticate message from %s\n", knot_addr2s(src_addr));
            char cmd[10];
            int validSig = knot_verify_message(src_addr, reply, replyLen, cmd);
            if (validSig) {
                if (strncmp("rnd", cmd, 3) == 0) {
                    knot_send_authenticated_reply(&knot_unauthenticatedLastMessageAddr);
                }
            }
        }
    }

    printf("End of knot_handle_authenticated_query for %s\n", knot_addr2s(src_addr));
}

int knot_verify_message(ipv6_addr_t *src_addr, uint8_t *data, size_t dataLen, char *cmd) {
    printf("Begin of knot_verify_message for %s\n", knot_addr2s(src_addr));
    
    printf("Begin CBOR decoding.\n");
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
    printf("End CBOR decoding.\n");

    printf("Begin verifying message.\n");
    if (cp_vbnn_ibs_user_verify(R, z, h, (uint8_t*)src_addr, 16, (uint8_t*)message, strlen(message), knot_remoteTA_key[0]) != 0) {
        printf("Signature is valid.\n");
        strncpy(cmd, message, 10);
        result = 1;
    }
    else {
        result = 0;
        printf("Signature is invalid.\n");
    }
    printf("End verifying message.\n");
    ps();
    free(message);
    ec_free(R); bn_free(z); bn_free(h);
    printf("End of knot_verify_message for %s\n", knot_addr2s(src_addr));
    return result;
}

void knot_send_authenticated_reply(ipv6_addr_t* target_address) {
    printf("Begin of knot_send_authenticated_reply for %s\n", knot_addr2s(target_address));
    uint8_t replyBuffer[200];
    uint8_t reply[10];
    rand_bytes(reply, 10);
    printf("Reply data: ");
    for (int n = 0; n < 10; n++) printf("%02x", reply[n]);
    printf("\n");
    (void)replyBuffer;
    printf("Begin signing data.\n");
    ec_t R;
    bn_t z;
    bn_t h;

    ec_null(R); ec_new(R);
    bn_null(z); bn_new(z);
    bn_null(h); bn_new(h);

    cp_vbnn_ibs_user_sign(R, z, h, (uint8_t*)target_address, 16, (uint8_t*)reply, sizeof(reply), knot_ownUser);
    printf("End signing data.\n");

    printf("Begin CBOR encoding.\n");
    cbor_stream_t stream;
    cbor_init(&stream, replyBuffer, sizeof(replyBuffer));
    cbor_serialize_map(&stream, 2);
    cbor_serialize_unicode_string(&stream, "msg");
    cbor_serialize_byte_stringl(&stream, (char*)reply, sizeof(reply));
    cbor_serialize_unicode_string(&stream, "sig");
    relic_ec2cbor_compressed(&stream, R);
    relic_bn2cbor(&stream, z);
    relic_bn2cbor(&stream, h);
    printf("End CBOR encoding.\n");

    ec_free(R); bn_free(z); bn_free(h);

    knot_send_udp_packet(*target_address, 4222, stream.data, stream.pos);

    ps();
    printf("End of knot_send_authenticated_reply for %s\n", knot_addr2s(target_address));
}

void knot_handle_ta_lookup_response(ipv6_addr_t* src_addr, uint8_t* reply, size_t replyLen) {
    printf("Begin of knot_handle_ta_lookup_response for %s\n", knot_addr2s(src_addr));
    cbor_stream_t stream;

    printf("Begin CBOR decoding.\n");
    cbor_init(&stream, (uint8_t*)reply, replyLen);
    char prefixPlustaPK[6 + 35];
    
    //cbor_deserialize_byte_string(&stream, 0, taPublicKeyBin, sizeof(taPublicKeyBin));
    printf("End CBOR decoding.\n");

    printf("Begin verifying TA public key agianst embedded hash.\n");
    /* 6 bytes global prefix */
    memcpy(prefixPlustaPK, src_addr, 6);
    /* FP_BYTES + 1 bytes TA public key */
    memcpy(prefixPlustaPK + 6, reply, replyLen);

    uint8_t hash[MD_LEN];
    md_map(hash, (uint8_t*)prefixPlustaPK, sizeof(prefixPlustaPK));
    if (util_cmp_const(((uint8_t*)src_addr) + 6, hash, 8) == CMP_EQ) {
        printf("TA public key verification successful.\n");
        
        printf("Store prefix/TA public key in cache.\n");
        memcpy(knot_remoteTA_prefix[0], src_addr, 14);
        relic_cbor2ec_compressed(knot_remoteTA_key[0], &stream, 0);
        printf("End verifying TA public key agianst embedded hash.\n");

        if (knot_unauthenticatedLastMessage) {
            printf("Authenticate last unauthenticated message from %s\n", knot_addr2s(&knot_unauthenticatedLastMessageAddr));
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
        printf("TA public key verification failed.\n");
        printf("End verifying TA public key agianst embedded hash.\n");
    }

    printf("End of knot_handle_ta_lookup_response for %s\n", knot_addr2s(src_addr));
}

int main(void)
{
    puts("RIOT IBC E2E Authentication for IoT Application");
    
    /* set 802.15.4 channel to 12 */
    //net_if_set_channel(7, 12);
    uint16_t channel = 12;
    ng_netapi_set(7, NETOPT_CHANNEL, 0, &channel, sizeof(uint16_t));
    puts("Set channel to 12");


    puts("Initialize RELIC...");
    core_init();
    ec_param_set_any();

    ec_null(knot_localTA);
    ec_new(knot_localTA);

    vbnn_ibs_user_null(knot_ownUser);
    vbnn_ibs_user_new(knot_ownUser);

    conf_print();
    puts("RELIC initialized!");


    // initiate dynamic initialization
    printf("Initiate dynamic device initialization\n");
    knot_start_server();
    knot_request_network_and_identity_from_gateway();

    posix_open(uart0_handler_pid, 0);

    for(;;) {
        sleep(30);
        printf(".\n");
    }

    vbnn_ibs_user_free(knot_ownUser);
    ec_free(knot_localTA);

    core_clean();

    /* should be never reached */
    return 0;
}
