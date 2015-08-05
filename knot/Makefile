# name of your application
APPLICATION = knot

# If no BOARD is found in the environment, use this default:
BOARD ?= native

# This has to be the absolute path to the RIOT base directory:
RIOTBASE ?= $(CURDIR)/../3rdParty/RIOT

BOARD_INSUFFICIENT_RAM := airfy-beacon chronos msb-430 msb-430h nrf51dongle \
                          nucleo-f334 pca10000 pca10005 redbee-econotag \
                          stm32f0discovery telosb wsn430-v1_3b wsn430-v1_4 \
                          yunjia-nrf51822 z1

BOARD_BLACKLIST        := arduino-mega2560
# arduino-mega2560: unknown error types (e.g. -EBADMSG)

# Include packages that pull up and auto-init the link layer.
# NOTE: 6LoWPAN will be included if IEEE802.15.4 devices are present
USEMODULE += ng_netif_default
USEMODULE += auto_init_ng_netif
# Specify the mandatory networking modules for IPv6 and UDP
USEMODULE += ng_ipv6_default
USEMODULE += ng_udp
# This application dumps received packets to STDIO using the pktdump module
USEMODULE += ng_pktdump
# Additional networking modules that can be dropped if not needed
USEMODULE += ng_icmpv6_echo
# Add also the shell, some shell commands (which are based on uart0 in this app)
USEMODULE += uart0
USEMODULE += shell
USEMODULE += shell_commands
USEMODULE += ps

# CBOR
USEMODULE += cbor

# Comment this out to disable code in RIOT that does safety checking
# which is not needed in a production environment but helps in the
# development process:
CFLAGS += -DDEVELHELP  -I$(CURDIR)/../3rdParty/NORX/norx3261/ref -I$(CURDIR)/../3rdParty/relic/include -I$(CURDIR)/build/relic/include
CFLAGS += -DTHREAD_STACKSIZE_MAIN=4000

LINKFLAGS += -L$(CURDIR)/build/relic/lib -lrelic_s

# Change this to 0 show compiler invocation lines by default:
QUIET ?= 1

include $(RIOTBASE)/Makefile.include
