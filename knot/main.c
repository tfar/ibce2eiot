#include <stdio.h>

#include "board_uart0.h"
#include "cbor.h"
#include "net/ng_netapi.h"
#include "net/ng_netif.h"
#include "net/netopt.h"
#include "posix_io.h"
#include "shell.h"
#include "unistd.h"

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

static const shell_command_t shell_commands[] = {
    { NULL, NULL, NULL }
};

uint8_t knot_configNonce[16];

static ec_t knot_localTA;
static vbnn_ibs_user_t knot_ownUser;

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

int set_address(const cbor_stream_t *stream, size_t offset) {
    uint8_t value[16];
    int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
    
    char addressStr[40];

    // set IPv6 address to value
    ipv6_addr_t addr;
    memcpy(&addr.u8, value, 16);

    ipv6_addr_to_str(addressStr, &addr, 40);


    if (ng_ipv6_netif_add_addr(7, &addr, 112, NG_IPV6_NETIF_ADDR_FLAGS_UNICAST) != NULL) {
        printf("Successfully set IPv6 address to %s\n", addressStr);
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
                offset += set_address(&stream, offset);
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

int main(void)
{
    shell_t shell;

    puts("RIOT IBC E2E Authentication for IoT Application");

    /* start shell */
    puts("All up, running the shell now");

    /* set 802.15.4 channel to 12 */
    //net_if_set_channel(7, 12);
    uint16_t channel = 12;
    ng_netapi_set(7, NETOPT_CHANNEL, 0, &channel, sizeof(uint16_t));
    puts("Set channel to 12");


    puts("initialize RELIC...");
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
    knot_start_server("4223");
    knot_request_network_and_identity_from_gateway();

    printf("Setting up shell now...\n");
    posix_open(uart0_handler_pid, 0);
    shell_init(&shell, shell_commands, UART0_BUFSIZE, uart0_readc, uart0_putc);
    shell_run(&shell);

    vbnn_ibs_user_free(knot_ownUser);
    ec_free(knot_localTA);

    core_clean();

    /* should be never reached */
    return 0;
}
