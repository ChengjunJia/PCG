#!/usr/bin/env python3
# coding: utf-8
#
#   Author: Chengjun Jia (jcjfly001@gmail.com)
#
#   Organization: Network Security Laboratory (NSLab),
#                 Research Institute of Information Technology (RIIT),
#                 Tsinghua University (THU)
#

import numpy as np
import matplotlib as mpl
import matplotlib.pyplot as plt
import os


def main():
    res = np.load("./res.npy", allow_pickle=True).item()
    print("All items are {key}".format( key = res.keys() ) )
    # y = getDensity(res['fw1_5K'], 10)
    # fig, ax = plt.subplots()
    # ax.plot(y)

    # Output the result 
    # ruleName = "fw1_10K"
    for ruleName in res.keys():
        with open( os.path.join(".", ruleName+".mark"), "w" ) as f:
            y = res[ruleName]
            for markItem in y:
                f.write("{mk}\n".format(mk=markItem))


def getDensity(x, sampleLen):
    """ get the Density calculation of input
    @para, x: a list of 0/1 to indict the marked in the ruleset
    @return, res: x * [1,...,1] (conv) 
    """
    xNum = len(x)
    assert(sampleLen < xNum)
    res = np.convolve(np.array(x),  np.ones(sampleLen, dtype=int), 'same')
    return res


if __name__ == '__main__':
    main()
