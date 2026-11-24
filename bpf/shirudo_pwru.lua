-- SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
-- Copyright Authors of Cilium

-- The decoder of the events map of the upatch pwru --shirudo-upatch
-- exports: PWRU_RECORD and the offsets pwru_emit_header() and
-- pwru_emit_record() of bpf/shirudo_pwru.c write at.
local RECORD = 200
local MAGIC = 0x55525750
local PROTOS = { [1] = "icmp", [6] = "tcp", [17] = "udp", [58] = "icmpv6",
	[132] = "sctp" }
local ETHERTYPES = { [0x0800] = "IPv4", [0x0806] = "ARP",
	[0x86dd] = "IPv6", [0x8100] = "802.1Q" }
local TCP_FLAGS = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" }

-- The argument that holds the drop reason, by the function that takes
-- one.
local REASON_ARG = { kfree_skb_reason = 32, sk_skb_reason_drop = 40 }

local function header(slot)
	if slot:u32(0) ~= MAGIC or slot:u16(6) ~= RECORD then
		return nil
	end
	return {
		boot_now_ns = slot:u64(16),
		since_ns = slot:u64(24),
		used = slot:u32(32),
		overflow = slot:u32(36),
		lost = slot:u32(40),
		peek = slot:u32(12) % 2 == 1,
	}
end

local function unix_nano(input, hdr, ts)
	if ts == "0" then
		return nil
	end
	return shirudo.u64_sub(input.timeUnixNano,
		shirudo.u64_sub(hdr.boot_now_ns, ts))
end

local function interval(input, hdr)
	return {
		since_unix_nano = unix_nano(input, hdr, hdr.since_ns),
		used = hdr.used,
		overflow = hdr.overflow,
		lost = hdr.lost,
		peek = hdr.peek,
	}
end

local function hex64(slot, off)
	return string.format("0x%08x%08x", slot:u32(off + 4), slot:u32(off))
end

local function ipv4(slot, off)
	return string.format("%d.%d.%d.%d", slot:u8(off), slot:u8(off + 1),
		slot:u8(off + 2), slot:u8(off + 3))
end

local function ipv6(slot, off)
	local groups = {}
	for i = 0, 7 do
		groups[i + 1] = string.format("%x",
			slot:u8(off + 2 * i) * 256 + slot:u8(off + 2 * i + 1))
	end
	return table.concat(groups, ":")
end

local function tcp_flags(bits)
	local names = {}
	for i = 1, #TCP_FLAGS do
		if bits % 2 == 1 then
			names[#names + 1] = TCP_FLAGS[i]
		end
		bits = math.floor(bits / 2)
	end
	return table.concat(names, "|")
end

-- The addresses, ports and protocol as pwru prints them, in one string,
-- as OTLP spends some 40 bytes on every field of a record.
local function tuple(slot)
	local version, proto = slot:u8(112), slot:u8(74)
	local host = version == 4 and ipv4 or version == 6 and ipv6
	if not host then
		return nil
	end
	local l4 = PROTOS[proto] or tostring(proto)
	local saddr, daddr = host(slot, 80), host(slot, 96)
	if slot:u8(113) == 0 then
		return string.format("%s->%s(%s)", saddr, daddr, l4)
	end
	return string.format(version == 6 and "[%s]:%d->[%s]:%d(%s)" or
		"%s:%d->%s:%d(%s)", saddr, slot:u16(76), daddr, slot:u16(78), l4)
end

local function record(input, hdr, slot)
	local protocol = slot:u16(72)
	local func = slot:cstring(136, 64)
	local r = {
		time_unix_nano = unix_nano(input, hdr, slot:u64(8)),
		skb = hex64(slot, 16),
		func = func ~= "" and func or hex64(slot, 24),
		cpu = slot:u32(48),
		pid = slot:u32(52),
		comm = slot:cstring(120, 16),
		netns = slot:u32(56),
		mark = slot:u32(60),
		ifindex = slot:u32(64),
		len = slot:u32(68),
		protocol = ETHERTYPES[protocol] or protocol,
	}
	if REASON_ARG[func] then
		r.reason = slot:u32(REASON_ARG[func])
	end
	r.tuple = tuple(slot)
	if slot:u8(113) == 1 and slot:u8(74) == 6 then
		r.tcp_flags = tcp_flags(slot:u8(75))
	end
	return r
end

function decode(input)
	local records, summary = {}, nil
	for _, page in ipairs(input.data.pages) do
		local slots = shirudo.page_slots(page, RECORD)
		local hdr = slots[1] and header(slots[1])
		if hdr then
			summary = summary or interval(input, hdr)
			for i = 2, #slots do
				if slots[i]:u32(4) % 2 == 1 then
					records[#records + 1] = record(input, hdr,
						slots[i])
				end
			end
		end
	end
	return {
		schema = 1,
		upatch = input.upatch,
		map = input.map,
		interval = summary,
		records = records,
	}
end
