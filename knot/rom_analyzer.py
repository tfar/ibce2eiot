#!/usr/bin/env python

# LINKFLAGS += -Wl,-Map=knot.map -Wl,--cref -Wl,--print-gc-sections
# append output of print-gc-sections to the map file

import re, sys

from collections import defaultdict


sizes = defaultdict(lambda: 0)


symbol_table = []
removed_symbols = []

removed_symbols_map = {}


with open(sys.argv[1]) as f:
	mergeWithNext = None
	for line in f:
		if mergeWithNext :
			line = " " + mergeWithNext.strip() + line
			mergeWithNext = None

		if re.match('^ (\.[^\s]+)$', line):
			mergeWithNext = line
		else:
			mo = re.match("^ (\.[^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)$", line)
			if mo:
				symbol_table.append(mo.groups())
			mo = re.match("^.+Removing unused section '([^\s]+)' in file '([^\s]+)'$", line)
			if mo:
				removed_symbols.append(mo.groups())

def ignoredSymbol(name):
	if name in (".debug_frame", ".comment", ".debug_str", ".debug_macro", ".debug_line", ".debug_abbrev", ".debug_info", ".debug_ranges", ".debug_loc", ".debug_aranges"):
		return True
	if name in (".group", ".ARM.attributes"):
		return True
	return False

sizes = defaultdict(lambda: 0)

def addSizeForModule(moduleName, size):
	sizes[moduleName] = int(sizes[moduleName]) + int(size)

def accountSymbol(symbol_name, size, filename):
	archive = None
	objectfile = None
	mo = re.match(".+\/([^\/]+)\(([^\)]+)\)$", filename)
	if mo:
		archive = mo.group(1)
		objectfile = mo.group(2)
	else:
		mo = re.match(".+\/([^\/]+)$", filename)
		if mo:
			objectfile = mo.group(1)
		else:
			print filename
	
	if not archive:
		addSizeForModule("RIOT", size)
	else:
		if archive == "librelic_s.a":
			addSizeForModule("RELIC", size)
		elif archive in ("at86rf2xx.a", "auto_init.a", "auto_init_ng_netif.a",
			"cbor.a", "core.a", "cortexm_common.a", "cpu.a",
			"hwtimer_compat.a", "inet_csum.a", "ipv6_addr.a",
			"ipv6_hdr.a", "ng_icmpv6.a", "ng_icmpv6_echo.a", "ng_ipv6.a",
			"ng_ipv6_hdr.a",
			"ng_ipv6_nc.a",
			"ng_ipv6_netif.a",
			"ng_ndp.a",
			"ng_ndp_internal.a",
			"ng_ndp_node.a",
			"ng_netapi.a",
			"ng_netif.a",
			"ng_netif_hdr.a",
			"ng_netreg.a",
			"ng_nomac.a",
			"ng_pktbuf_static.a",
			"ng_pktdump.a",
			"ng_sixlowpan.a",
			"ng_sixlowpan_ctx.a",
			"ng_sixlowpan_frag.a",
			"ng_sixlowpan_iphc.a",
			"ng_sixlowpan_netif.a",
			"ng_udp.a",
			"od.a",
			"periph.a",
			"periph_common.a",
			"posix.a",
			"ps.a",
			"random.a",
			"samr21-xpro_base.a",
			"timex.a",
			"uart0.a",
			"uart_stdio.a",
			"udp.a",
			"vtimer.a"):
			addSizeForModule("RIOT", size)
		elif archive in ("libc_nano.a", "libgcc.a"):
			addSizeForModule("C", size)
		elif archive == "knot.a":
			if objectfile == "norx_impl.o":
				addSizeForModule("NORX", size)
			else:
				addSizeForModule("APP", size)
		else:
			print archive, filename
			addSizeForModule("OTHER", size)

for remsym in removed_symbols:
	(symbol, filename) = remsym
	removed_symbols_map[remsym] = filename

for symbol in symbol_table:
	(symbol_name, foo, size_in_hex, filename) = symbol
	if not (symbol_name, filename) in removed_symbols_map:
		if not ignoredSymbol(symbol_name):
			accountSymbol(symbol_name, int(size_in_hex, 16), filename)

total = 0
print("Module Sizes")
print("============")
for k, v in sizes.iteritems():
	total = total + int(v)
for k, v in sizes.iteritems():
	print "%s %s %s %%" % (k.ljust(15), str(v).rjust(15), str("%.1f" % round(float(v)/total * 100, 1)).rjust(15))
print "Total: %s" % total