#!/usr/bin/env python2
# coding: utf-8
#
#   Author: Xiang Wang (xiang.wang.s@gmail.com)
#
#   Organization: Network Security Laboratory (NSLab),
#                 Research Institute of Information Technology (RIIT),
#                 Tsinghua University (THU)
#

import re
import copy
import itertools
import collections


DIM_POINT_BITS = [32, 32, 16, 16, 8]
DIM_SIP, DIM_DIP, DIM_SPORT, DIM_DPORT, DIM_PROTO, DIM_MAX = range(6)
UINT32_MAX, UINT16_MAX, UINT8_MAX = ((1 << i) - 1 for i in [32, 16, 8])
DIM_POINT_MAX = [UINT32_MAX, UINT32_MAX, UINT16_MAX, UINT16_MAX, UINT8_MAX]


def is_range_overlap(left, right):
    return left[0] <= right[1] and left[1] >= right[0]


def gen_prefix_mask(mask_len, bits):
    return (1 << bits) - (1 << (bits - mask_len))

def gen_suffix_mask(mask_len):
    return (1 << mask_len) - 1


# rng format:
# [begin, end]
def prefix2range(prfx, bits):
    return [prfx[0] & gen_prefix_mask(prfx[1], bits),
            prfx[0] | gen_suffix_mask(bits - prfx[1])]

# prfx format:
# [[value, prefix_len], ...]
def range2prefix(rng, bits):
    prfx = []
    work_queue = collections.deque()
    work_queue.append((list(rng), [0, 0]))

    while work_queue:
        r, p = work_queue.popleft()

        if r == prefix2range(p, bits):
            prfx.append(p)
            continue

        p[1] += 1
        cut = p[0] | (1 << (bits - p[1]))

        if r[1] < cut:
            work_queue.append((r, p))
        elif r[0] >= cut:
            p[0] = cut
            work_queue.append((r, p))
        else:
            work_queue.append(([r[0], cut - 1], p))
            r[0] = cut
            work_queue.append((r, [cut, p[1]]))

    return prfx


# rule format:
# [[sip_begin, sip_end], ..., [proto_begin, proto_end], [pri]]
def load_rules(s_rule_file):
    rule_set = []
    rule_fmt = re.compile(r'^@(\d+).(\d+).(\d+).(\d+)/(\d+) '
            r'(\d+).(\d+).(\d+).(\d+)/(\d+) '
            r'(\d+) : (\d+) '
            r'(\d+) : (\d+) '
            r'(0x[\da-fA-F]+)/(0x[\da-fA-F]+)$')

    for idx, line in enumerate(open(s_rule_file)):
        sip0, sip1, sip2, sip3, sip_mask_len, \
        dip0, dip1, dip2, dip3, dip_mask_len, \
        sport_begin, sport_end, \
        dport_begin, dport_end, \
        proto, proto_mask = \
        (eval(rule_fmt.match(line).group(i)) for i in range(1, 17))

        sip0 = (sip0 << 24) | (sip1 << 16) | (sip2 << 8) | sip3
        sip_begin, sip_end = prefix2range((sip0, sip_mask_len), 32)

        dip0 = (dip0 << 24) | (dip1 << 16) | (dip2 << 8) | dip3
        dip_begin, dip_end = prefix2range((dip0, dip_mask_len), 32)

        if proto_mask == 0xff:
            proto_begin = proto
            proto_end = proto
        else:
            proto_begin = 0
            proto_end = 0xff

        rule_set.append([[sip_begin, sip_end], [dip_begin, dip_end],
                [sport_begin, sport_end], [dport_begin, dport_end],
                [proto_begin, proto_end], [idx]])

    return rule_set

# dim_range format:
# [range0_begin, range0_end, ...]
def shadow_rules(rule_set, dim):
    point_set = set()

    for rule in rule_set:
        point_set.add((rule[dim][0] << 1) + 0)  # 0: begin
        point_set.add((rule[dim][1] << 1) + 1)  # 1: end

        if rule[dim][0]:
            point_set.add(((rule[dim][0] - 1) << 1) + 1)

        if rule[dim][1] != DIM_POINT_MAX[dim]:
            point_set.add(((rule[dim][1] + 1) << 1) + 0)

    return [point >> 1 for point in sorted(point_set)]

# rule format:
# [[sip_value, sip_prfx_len], ..., [proto_value, proto_prfx_len], [pri]]
def split_rule(rule):
    prfx = []

    for dim in range(DIM_MAX):
        prfx.append(range2prefix(rule[dim], DIM_POINT_BITS[dim]))

    prfx.append(rule[DIM_MAX])

    return [list(r) for r in itertools.product(prfx[DIM_SIP], prfx[DIM_DIP],
        prfx[DIM_SPORT], prfx[DIM_DPORT], prfx[DIM_PROTO], prfx[DIM_MAX])]


# range_stats format:
# {(begin, end): [rule_id, ...]}
def gen_range_stats(rule_set, dim):
    range_stats = collections.defaultdict(list)

    for rule in rule_set:
        key = (rule[dim][0], rule[dim][1])
        range_stats[key].append(rule[DIM_MAX][0])

    return range_stats

# range_len_stats format:
# {len: set((begin, end), ...)}
def gen_range_len_stats(rule_set, dim):
    range_len_stats = collections.defaultdict(set)

    for rule in rule_set:
        key = rule[dim][1] - rule[dim][0] + 1
        range_len_stats[key].add(tuple(rule[dim]))

    return range_len_stats


# range_layer format:
# [{'ranges': set((begin, end), ...), 'rules': [rule_id, ...]}, ...]
def layer_ranges(range_stats, range_len_stats, bottom_up):
    range_layer = []
    range_len_proc = copy.deepcopy(range_len_stats)

    while range_len_proc:
        # build a new layer
        layer = len(range_layer)
        range_layer.append({'ranges': set(), 'rules': []})

        for rng_len in sorted(range_len_proc, reverse=bottom_up):
            for rng_proc in sorted(range_len_proc[rng_len],
                    key=lambda rng: rng[0]):

                # check overlap against selected ranges in current layer
                for rng_selected in range_layer[layer]['ranges']:
                    if is_range_overlap(rng_proc, rng_selected):
                        break
                else:
                    range_layer[layer]['ranges'].add(rng_proc)
                    range_layer[layer]['rules'].extend(range_stats[rng_proc])

                    range_len_proc[rng_len].remove(rng_proc)
                    if not range_len_proc[rng_len]:
                        range_len_proc.pop(rng_len)

    return range_layer

# address_layer format:
# [{'ranges': set((begin, end), ...), 'rules': set(rule_id, ...)}, ...]
def layer_addresses(sip_range_stats, dip_range_stats,
        sip_range_len_stats, dip_range_len_stats, bottom_up):
    ip_range_stats = copy.deepcopy(sip_range_stats)
    ip_range_len_stats = copy.deepcopy(sip_range_len_stats)

    for dip_range in dip_range_stats:
        ip_range_stats[dip_range].extend(dip_range_stats[dip_range])

    for dip_range_len in dip_range_len_stats:
        ip_range_len_stats[dip_range_len].update(
                dip_range_len_stats[dip_range_len])

    address_layer = layer_ranges(ip_range_stats, ip_range_len_stats, bottom_up)

    for address in address_layer:
        address['rules'] = set(address['rules'])

    return address_layer

