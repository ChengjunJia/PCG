#!/usr/bin/env python3
# coding: utf-8
#
#   Author: Chengjun Jia (jcjfly001@gmail.com)
#
#   Organization: Network Security Laboratory (NSLab),
#                 Research Institute of Information Technology (RIIT),
#                 Tsinghua University (THU)
#

import pc
import sys
import time
import os

from copy import deepcopy
from policyspace import HyperRect, PolicySpace

import numpy as np

import logging

def createLogger():
    logger = logging.getLogger('logger')
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler('main.log')
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s %(levelname)s:  %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger


# Get the results by calculating: A_j \bigcap (\bigcup A_i (i: 0->j-1) )
def analyzeRulesetwithUnion(filename):
    global logger
    rs = pc.load_rules(filename)
    # 尝试计算有多少规则是Mark规则
    start = time.time()
    num = 1
    total_num = 1
    already_union_set = PolicySpace([HyperRect(deepcopy(rs[0][:5]))])
    logger.info("="*50)
    isMarkList = [1]
    for r in rs[1:-1]:
        total_num += 1

        cur_rule =  PolicySpace([HyperRect(deepcopy(r[:5]))])
        if not already_union_set.__and__(cur_rule):
            num += 1
            isMarkList.append(1)
        else:
            isMarkList.append(0)
        already_union_set.or_rect( HyperRect(r[:5]) )
    end = time.time()
    logger.info("We have {num}/{total_num} for the rule {rulename}".format(num=num, total_num=total_num, rulename=filename))
    logger.info("The time runs for {total_time:.3f}s".format(total_time=end-start))
    return isMarkList


# Get the results by calculating: \bigcup (A_j \bigcap A_i) (i: 0->j-1) 
def analyzeRuleset(filename):
    global logger
    rs = pc.load_rules(filename)
    start = time.time()
    logger.info("="*50)
    # Convert rules into the policySpace
    rsPolicySpaceList = []
    for r in rs:
        cur_rule = PolicySpace([HyperRect(deepcopy(r[:5]))])
        rsPolicySpaceList.append(cur_rule)
    ruleNum = len(rsPolicySpaceList)
    logger.info("Finish the PolicySpace Analysis.")
    # init the mark List
    Marknum = 1 
    isMarkList = [1]
    for i in range(1, ruleNum):
        isMark = 1
        curRule = rsPolicySpaceList[i]
        for j in range(0, i):
            cmpRule = rsPolicySpaceList[j]
            if not curRule.__and__(cmpRule): # curRule /\ cmpRule == None
                continue
            else:
                isMark = 0
                break
        isMarkList.append(isMark)
        Marknum += isMark
    end = time.time()
    total_num = ruleNum
    logger.info("We have {num}/{total_num} for the rule {rulename}".format(num=Marknum, total_num=total_num, rulename=filename))
    logger.info("The time runs for {total_time}s".format(total_time=end-start))
    return isMarkList


def init():
    global logger
    logger = createLogger()
    ruleRootPath = os.path.join(".", "pc_plat", "rule_trace", "rules", "origin")
    g = os.walk(ruleRootPath)
    resMap = {}
    for path, dir_list, file_list in g:
        for filename in file_list:
            filePath = os.path.join(ruleRootPath, filename)
            ruleRes = analyzeRuleset(filePath)
            resMap[filename] = ruleRes
    np.save("res.npy", resMap)

def getRuleSetResult():
    ruleName = "fw1_10k_CutSplit"
    fn = os.path.join(".", ruleName)
    res = analyzeRuleset(fn)
    with open( os.path.join(".", ruleName+".mark"), "w" ) as f:
        y = res
        for markItem in y:
            f.write("{mk}\n".format(mk=markItem))

if __name__ == "__main__":
    global logger
    if 'logger' not in locals().keys() or logger != logging.getLogger('logger'):
        logger = logging.getLogger('logger')
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
    
        formatter = logging.Formatter('%(asctime)s %(levelname)s:  %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # init()
    getRuleSetResult()

# filename = './pc_plat-master/rule_trace/rules/origin/fw1_5K'
