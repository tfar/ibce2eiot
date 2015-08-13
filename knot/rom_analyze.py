#!/usr/bin/env python


import subprocess
import re


from collections import defaultdict

sizes = defaultdict(lambda: 0)

def re_match_any(regex_list, string):
	for regex in regex_list:
		if (re.match(regex, string)) :
			return True
	return False

def addSizeForModule(moduleName, size):
	sizes[moduleName] = int(sizes[moduleName]) + int(size)

proc = subprocess.Popen(['arm-none-eabi-nm', '-S', '--size-sort', '--radix=dec', 'bin/samr21-xpro/knot.elf'],stdout=subprocess.PIPE)
while True:
  line = proc.stdout.readline()
  if line != '':
	#the real code does filtering here
	#print "stdout:", line.rstrip()
	symbol_value, symbol_size, symbol_type, symbol_name = line.rstrip().split(' ')

	# relic matches
	if re.match('^fp_.+$', symbol_name):
		addSizeForModule("RELIC/FP", symbol_size)
	elif re.match('^ed_.+$', symbol_name):
		addSizeForModule("RELIC/ED", symbol_size)
	elif re.match('^bn_.+$', symbol_name):
		addSizeForModule("RELIC/BN", symbol_size)
	elif re.match('^blake2s_?.*$', symbol_name):
		addSizeForModule("RELIC/MD", symbol_size)
	elif re.match('^md_.+$', symbol_name):
		addSizeForModule("RELIC/MD", symbol_size)
	elif re.match('^rand_.+$', symbol_name):
		addSizeForModule("RELIC/RAND", symbol_size)
	elif re.match('^util_.+$', symbol_name):
		addSizeForModule("RELIC/UTIL", symbol_size)
	elif re.match('^dv_.+$', symbol_name):
		addSizeForModule("RELIC/DV", symbol_size)
	# NORX
	elif re.match('^norx_.+$', symbol_name):
		addSizeForModule("NORX", symbol_size)
	elif re.match('^burn$', symbol_name):
		addSizeForModule("NORX", symbol_size)
	# stdlib (C)
	elif re.match('^str.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^_kill.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^_malloc.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^_read.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^_realloc.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^_write.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^_.*print.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^__u?div.*$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re.match('^memcmp$', symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	elif re_match_any(['^_strtol_r', '^__sflush_r', '^_strtoul_r', '^_puts_r', '^__ssputs_r', '^_free_r'
			'^viprintf', '^vprintf', '^__sseek', '^__sfputc_r', '^fflush', '^__sread', '^__sfputs_r'
			'^fprintf', '^fiprintf', '^malloc', '^_close_r', '^__swrite', '^__libc_init_array', 
			'^_free_r', '^_fstat_r'], symbol_name):
		addSizeForModule("STDLIB", symbol_size)
	# RIOT
	# RIOT Radio
	elif re.match('^at86rf2xx_.*$', symbol_name):
		addSizeForModule("RIOT/RADIO", symbol_size)
	# RIOT CBOR
	elif re.match('^cbor_.*$', symbol_name):
		addSizeForModule("RIOT/CBOR", symbol_size)	
	# RIOT Timer
	elif re.match('^vtimer_.+$', symbol_name):
		addSizeForModule("RIOT/TIMER", symbol_size)
	elif re.match('^timer_.+$', symbol_name):
		addSizeForModule("RIOT/TIMER", symbol_size)
	# RIOT Network
	elif re.match('^ng_sixlowpan_.+$', symbol_name):
		addSizeForModule("RIOT/6LOWPAN", symbol_size)
	elif re.match('^ng_ndp_.+$', symbol_name):
		addSizeForModule("RIOT/NDP", symbol_size)
	elif re.match('^ipv6_.+$', symbol_name):
		addSizeForModule("RIOT/IPV6", symbol_size)
	elif re.match('^ng_ipv6_.+$', symbol_name):
		addSizeForModule("RIOT/IPV6", symbol_size)
	elif re.match('^inet_.+$', symbol_name):
		addSizeForModule("RIOT/INET", symbol_size)
	elif re.match('^_?fib_.+$', symbol_name):
		addSizeForModule("RIOT/FIB", symbol_size)
	elif re.match('^ng_udp_.+$', symbol_name):
		addSizeForModule("RIOT/UDP", symbol_size)
	elif re.match("^universal_address_.*", symbol_name):
		addSizeForModule("RIOT/NETWORK", symbol_size)
	elif re.match("^ng_netif_.*$", symbol_name):
		addSizeForModule("RIOT/NETWORK", symbol_size)
	elif re.match("^ng_pktbuf_.*$", symbol_name):
		addSizeForModule("RIOT/PKTBUF", symbol_size)
	elif re.match("^_pktbuf.*$", symbol_name):
		addSizeForModule("RIOT/PKTBUF", symbol_size)
	elif re.match("^ng_netapi_.*", symbol_name):
		addSizeForModule("RIOT/NETAPI", symbol_size)
	elif re.match("^ng_icmpv6_.*", symbol_name):
		addSizeForModule("RIOT/ICMPV6", symbol_size)
	# RIOT UART
	elif re.match("^uart0?_.*$", symbol_name):
		addSizeForModule("RIOT/UART", symbol_size)
	# Knot (Application)
	elif re.match("^knot_.*$", symbol_name):
		addSizeForModule("APP", symbol_size)
	elif re.match("^main$", symbol_name):
		addSizeForModule("APP", symbol_size)
	elif re.match("^main_stack$", symbol_name):
		addSizeForModule("APP", symbol_size)
	elif re.match("^relic_.*", symbol_name):
		addSizeForModule("APP", symbol_size)
	else :
		print "Unknown: %s, %s, %s" % (symbol_name, symbol_size, symbol_type)
		addSizeForModule("OTHER", symbol_size)
  else:
	break

print("Module Sizes")
print("============")
for k, v in sizes.iteritems():
	print "%s %s" % (k.ljust(15), str(v).rjust(15))