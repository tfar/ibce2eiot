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

extern int udp_cmd(int argc, char **argv);

extern void send(char *addr_str, char *port_str, char *data);

const uint8_t confRequestKey[16] = {0x82, 0x02, 0x1a, 0xb1, 0x47, 0xd8, 0xbb, 0x75, 
                                    0x91, 0x17, 0x4d, 0x9c, 0x81, 0x74, 0x3e, 0x3b};
const uint8_t confResponseKey[16] ={0xbe, 0x87, 0x7c, 0x23, 0xf0, 0x6c, 0x59, 0x69,
                                    0x92, 0xda, 0xe9, 0xd1, 0xf2, 0xf9, 0x36, 0x7c};

static const shell_command_t shell_commands[] = {
    { "udp", "send data over UDP and listen on UDP ports", udp_cmd },
    { NULL, NULL, NULL }
};

uint8_t configNonce[16];

static ec_t localTA;
static vbnn_ibs_user_t ownUser;


const uint8_t dynamicConfigurationReply[] = {
    0xc6, 0xba, 0x4e, 0x90, 0x38, 0x13, 0x22, 0x43, 0x12, 0x67, 0x27, 0x2f, 0xeb, 0xae, 0x81, 0xa5, 0x24, 0xcd, 0xf2, 0x5a, 0x91, 0x29, 0x86, 0x7d, 0x8b, 0xd7, 0x77, 0xab, 0x3d, 0x23, 0xb7, 0xbf, 0x2a, 0x0d, 0xd1, 0xab, 0x78, 0xb1, 0xf9, 0x19, 0x13, 0xba, 0xfe, 0x4b, 0x34, 0x5d, 0xc7, 0xd4, 0xf0, 0x9a, 0xbc, 0x83, 0xa9, 0xd6, 0xc2, 0x7d, 0xc2, 0xc2, 0x57, 0x60, 0x9a, 0xde, 0x85, 0xe8, 0x96, 0x16, 0xf0, 0x5f, 0x24, 0x7d, 0x0f, 0x93, 0xf5, 0xd6, 0x0c, 0x36, 0xfb, 0xe9, 0x9e, 0x58, 0x8c, 0x68, 0x31, 0xe5, 0xb0, 0x15, 0x57, 0x03, 0xc8, 0x93, 0x8b, 0xc9, 0xec, 0x27, 0x9a, 0x0f, 0x5d, 0xca, 0x71, 0x68, 0xd8, 0x62, 0x12, 0x91, 0x86, 0x33, 0xa4, 0xe9, 0x0b, 0x93, 0x14, 0x26, 0x99, 0xe0, 0x49, 0xdf, 0xe6, 0x7a, 0x73, 0x15, 0x0f, 0xaf, 0xa3, 0x15, 0xab, 0xb7, 0x5e, 0x80, 0xf3, 0xa5, 0xb1, 0x96, 0x42, 0xab, 0xe3, 0x9f, 0x4f, 0x3b, 0xa4, 0x55, 0x82, 0x2f, 0x05, 0xa8, 0x28, 0xae, 0xee, 0x1f, 0x8d, 0x7a
};

void request_network_and_identity_from_gateway(void) {
    uint8_t cborBuffer[50];
    cbor_stream_t stream;
    puts("request_network_and_identity_from_gateway: begin");
    // generate nonce
    rand_bytes(configNonce, 16);

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
        plaintext, plaintextLen, trailer, trailerLen, configNonce, confRequestKey);
    //send("ff02::0e2e:0ecc", "20000", "Hello World!");

    cbor_clear(&stream);

    // compute request message
    cbor_serialize_array(&stream, 2);
    cbor_serialize_byte_stringl(&stream, (char*)configNonce, 16);
    cbor_serialize_byte_stringl(&stream, (char*)requestCiphertext, requestCiphertextLen);

    ng_ipv6_addr_t toAddress;
    ng_ipv6_addr_from_str(&toAddress, "ff02::0e2e:0ecc");

    send_udp_packet(toAddress, 4223, stream.data, stream.pos);

    free(requestCiphertext);
    requestCiphertext = 0;
    puts("request_network_and_identity_from_gateway: end");
}

int set_address(const cbor_stream_t *stream, size_t offset) {
    uint8_t value[16];
    int ret = cbor_deserialize_byte_string(stream, offset, (char*)value, sizeof(value));
    
    char addressStr[40];

    // set IPv6 address to value
    ng_ipv6_addr_t addr;
    memcpy(&addr.u8, value, 16);

    ng_ipv6_addr_to_str(addressStr, &addr, 40);


    if (ng_ipv6_netif_add_addr(7, &addr, 112, NG_IPV6_NETIF_ADDR_FLAGS_UNICAST) != NULL) {
        printf("Successfully set IPv6 address to %s", addressStr);
    }
    else {
        printf("Failed to set IPv6 address!\n");
    }


    return ret;
}

void handle_dynamic_configuration_reply(const uint8_t* reply, size_t replyLen) {
    puts("Attempt do decrypt dynamic configuration response.");
    uint8_t* plaintext = malloc(replyLen);
    size_t plaintextLen = replyLen;

    const uint8_t* header = 0;
    size_t headerLen = 0;
    const uint8_t* trailer = 0;
    size_t trailerLen = 0;
    int result = norx_aead_decrypt(plaintext, &plaintextLen, header, headerLen,
            reply, replyLen, trailer, trailerLen, configNonce, confResponseKey);

    if (result == 0) {
        cbor_stream_t stream;
        cbor_init(&stream, plaintext, plaintextLen);

        size_t mapLength = 0;
        size_t offset = cbor_deserialize_map(&stream, 0, &mapLength);

        for (int mapIndex = 0; mapIndex < mapLength; mapIndex++) {
            char key[10];
            offset += cbor_deserialize_unicode_string(&stream, offset, key, 10);

            if (strncmp("mpk", key, 3) == 0) {
                offset += relic_cbor2ec_compressed(localTA, &stream, offset);
            }
            else if (strncmp("id", key, 2) == 0) {
                offset += set_address(&stream, offset);
            }
            else if (strncmp("key", key, 3) == 0) {
                size_t length;
                offset += cbor_deserialize_array(&stream, offset, &length);
                assert(length == 2);
                offset += relic_cbor2ec_compressed(ownUser->R, &stream, offset);
                offset += relic_cbor2bn(ownUser->s, &stream, offset);
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
    posix_open(uart0_handler_pid, 0);
    shell_init(&shell, shell_commands, UART0_BUFSIZE, uart0_readc, uart0_putc);

    /* set 802.15.4 channel to 12 */
    //net_if_set_channel(7, 12);
    uint16_t channel = 12;
    ng_netapi_set(7, NETOPT_CHANNEL, 0, &channel, sizeof(uint16_t));
    puts("Set channel to 12");


    puts("initialize RELIC...");
    core_init();
    ec_param_set_any();

    ec_null(localTA);
    ec_new(localTA);

    vbnn_ibs_user_null(ownUser);
    vbnn_ibs_user_new(ownUser);

    conf_print();
    puts("RELIC initialized!");


    // initiate dynamic initialization
    puts("Initiate dynamic device initialization.");
    start_server("4223");
    
    request_network_and_identity_from_gateway();

    handle_dynamic_configuration_reply(dynamicConfigurationReply, 150);

    shell_run(&shell);

    vbnn_ibs_user_free(ownUser);
    ec_free(localTA);

    core_clean();

    /* should be never reached */
    return 0;
}
