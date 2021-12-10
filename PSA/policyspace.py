#!/usr/bin/env python2
# coding: utf-8
#
#   Author: Xiang Wang (xiang.wang.s@gmail.com)
#
#   Organization: Network Security Laboratory (NSLab),
#                 Research Institute of Information Technology (RIIT),
#                 Tsinghua University (THU)
#

from copy import deepcopy
from operator import mul
from itertools import chain
import sys

if sys.version_info.major == 3:
    from functools import reduce # 对于Python3版本, 导入reduce函数

class HyperRect(object):
    def __init__(self, dims):
        self.dims = dims

    # is_equal
    def __eq__(self, value):
        return self.dims == value.dims

    # is_subset
    def __le__(self, value):
        for sd, vd in zip(self.dims, value.dims):
            if sd[0] < vd[0] or sd[1] > vd[1]:
                return False
        return True

    # is_intersect
    def __mul__(self, value):
        for sd, vd in zip(self.dims, value.dims):
            if sd[0] > vd[1] or sd[1] < vd[0]:
                return False
        return True

    # relation
    # None: not intersect, 0: partially overlap, -1: subset, 1: contain)
    def __div__(self, value):
        subset = contain = True
        for sd, vd in zip(self.dims, value.dims):
            if sd[0] > vd[1] or sd[1] < vd[0]:
                return None
            if subset and (sd[0] < vd[0] or sd[1] > vd[1]):
                subset = False
            if contain and (sd[0] > vd[0] or sd[1] < vd[1]):
                contain = False
        return -1 if subset else 1 if contain else 0

    # intersect
    def __and__(self, value):
        dims = []
        for sd, vd in zip(self.dims, value.dims):
            if sd[0] > vd[1] or sd[1] < vd[0]:
                return []
            dims.append([max(sd[0], vd[0]), min(sd[1], vd[1])])
        return [HyperRect(dims)]
    
    # intersect for each field
    def and_dim_with(self, value):
        dims = []
        for sd, vd in zip(self.dims, value.dims):
            if sd[0] > vd[1] or sd[1] < vd[0]:
                dims.append(0)
            else:
                dims.append(1)
        return dims

    # subtract
    def __sub__(self, value):
        relation = self.__div__(value)
        return [deepcopy(self)] if relation is None else \
                HyperRect.clip(self.dims, value.dims, False) \
                if relation >= 0 else []

    # union
    def __or__(self, value):
        smetric = vmetric = 0
        for sd, vd in zip(self.dims, value.dims):
            if sd[0] > vd[1] or sd[1] < vd[0]:
                return [deepcopy(self), deepcopy(value)]
            elif sd[0] >= vd[0] and sd[1] <= vd[1]:
                smetric += 1
            elif sd[0] <= vd[0] and sd[1] >= vd[1]:
                vmetric += 1
        if vmetric == len(self.dims):
            return [deepcopy(self)]
        elif smetric == len(self.dims):
            return [deepcopy(value)]
        else:
            minuend, subtrahend = (self, value) \
                    if smetric >= vmetric else (value, self)
            result = HyperRect.clip(minuend.dims, subtrahend.dims, False)
            result.append(deepcopy(subtrahend))
            return result

    @property
    def volume(self):
        return reduce(mul, (d[1] - d[0] + 1 for d in self.dims))

    @classmethod
    def clip(cls, clipped, clipping, inplace):
        result = []
        if not inplace: clipped = deepcopy(clipped)
        for i in range(len(clipped)):
            if clipped[i][0] < clipping[i][0]:
                dims = deepcopy(clipped)
                dims[i][1] = clipping[i][0] - 1
                result.append(HyperRect(dims))
                clipped[i][0] = clipping[i][0]
            if clipped[i][1] > clipping[i][1]:
                dims = deepcopy(clipped)
                dims[i][0] = clipping[i][1] + 1
                result.append(HyperRect(dims))
                clipped[i][1] = clipping[i][1]
        return result


class PolicySpace(object):
    def __init__(self, rects):
        self.rects = rects

    # is_equal
    def __eq__(self, value):
        return self.__le__(value) and value.__le__(self)

    # is_subset
    def __le__(self, value):
        for sr in self.rects:
            rects = (sr.__and__(vr) for vr in value.rects)
            if sum(r[0].volume for r in rects if r) != sr.volume:
                return False
        return True

    # is_intersect
    def __mul__(self, value):
        for vr in value.rects:
            for sr in self.rects:
                if vr.__mul__(sr):
                    return True
        return False

    # intersect
    def __and__(self, value):
        rects = list(chain.from_iterable(vr.__and__(sr)
            for vr in value.rects for sr in self.rects))
        return PolicySpace(rects) if rects else None
    
    # intersect on the specified dims
    def is_overlap(self, value, specified_dim):
        assert( len(value.rects) == 1 )
        assert( len(self.rects) == 1 )
        res = value.rects[0].and_dim_with( self.rects[0] )
        for d in specified_dim:
            if res[d] == 0:
                # Any dim is not overlap --> they are not overlapped
                return False
        return True

    # subtract
    def __sub__(self, value):
        # deepcopy once
        rects = list(chain.from_iterable(sr.__sub__(value.rects[0])
            for sr in self.rects))
        if not rects: return None
        # update inplace
        result = PolicySpace(rects)
        for vr in value.rects[1:]:
            result.sub_rect(vr)
            if not result.rects: return None
        return result

    # union
    def __or__(self, value):
        minuend, subtrahend = (self, value) \
                if len(self.rects) >= len(value.rects) else (value, self)
        srects = deepcopy(subtrahend.rects)
        # deepcopy once
        rects = list(chain.from_iterable(sr.__sub__(subtrahend.rects[0])
            for sr in minuend.rects))
        if not rects: return PolicySpace(srects)
        # update inplace
        result = PolicySpace(rects)
        for vr in subtrahend.rects[1:]:
            result.sub_rect(vr)
            if not result.rects: return PolicySpace(srects)
        result.rects.extend(srects)
        return result

    # intersect a rectangle (inplace)
    def and_rect(self, rect):
        rects = []
        for sr in self.rects:
            for sd, vd in zip(sr.dims, rect.dims):
                if sd[0] > vd[1] or sd[1] < vd[0]:
                    break
                if sd[0] < vd[0]: sd[0] = vd[0]
                if sd[1] > vd[1]: sd[1] = vd[1]
            else:
                rects.append(sr)
        self.rects = rects

    # subtract a rectangle (inplace)
    def sub_rect(self, rect):
        rects = []
        for sr in self.rects:
            relation = sr.__div__(rect)
            if relation is None:
                rects.append(sr)
            elif relation >= 0:
                rects.extend(HyperRect.clip(sr.dims, rect.dims, True))
        self.rects = rects

    # union a rectangle (inplace)
    def or_rect(self, rect):
        rects = []
        for i, sr in enumerate(self.rects):
            relation = sr.__div__(rect)
            if relation is None:
                rects.append(sr)
            elif relation == 0:
                rects.extend(HyperRect.clip(sr.dims, rect.dims, True))
            elif relation > 0:
                rects.extend(self.rects[i:])
                break
        else:
            rects.append(deepcopy(rect))
        self.rects = rects

