#include <stdio.h>

#include "board_uart0.h"
#include "cbor.h"
#include "net/ng_netapi.h"
#include "net/ng_netif.h"
#include "net/ng_netopt.h"
#include "posix_io.h"
#include "shell.h"
#include "unistd.h"

#include <relic.h>
#include <norx.h>

#include <norx.c>

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

void request_network_and_identity_from_gateway(void) {
    uint8_t cborBuffer[50];
    cbor_stream_t stream;

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
    ng_netapi_set(7, NG_NETOPT_CHANNEL, 0, &channel, sizeof(uint16_t));
    puts("Set channel to 12");


    puts("initialize RELIC...");
    core_init();
    ec_param_set_any();
    conf_print();
    puts("RELIC initialized!");

    // initiate dynamic initialization
    puts("Initiate dynamic device initialization.");
    start_server("4223");
    request_network_and_identity_from_gateway();

    shell_run(&shell);

    core_clean();

    /* should be never reached */
    return 0;
}
