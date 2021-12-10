# -*- coding: utf-8 -*-
"""
Created on Thu Dec  9 11:23:42 2021

@author: Jake
"""

import networkx as nx
import logging
import numpy as np
import sys
import time
from copy import deepcopy
import os
from collections import Counter
import numpy.matlib
from PIL import Image


import pc
from policyspace import PolicySpace, HyperRect

# %% init logger
def initLogger():
    global logger
    if 'logger' not in locals().keys() or logger != logging.getLogger('logger'):
        logger = logging.getLogger('logger')
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
    
        formatter = logging.Formatter('%(asctime)s %(levelname)s:  %(message)s')
        ch.setFormatter(formatter)
        logger.addHandler(ch)
initLogger()

def getRuleMat(filename):
    global logger
    rs = pc.load_rules(filename)
    start = time.time()
    logger.info("="*50)
    # Convert rules into the policyspace
    rsPolicySpaceList = []
    for r in rs:
        cur_rule = PolicySpace([HyperRect(deepcopy(r[:5]))])
        rsPolicySpaceList.append(cur_rule)
    ruleNum = len(rsPolicySpaceList)
    logger.info("Finish the PolicySpace Convert.")
    # init the matrix
    result = np.matlib.eye(n=ruleNum, dtype=int)
    for i in range(1, ruleNum):
        curRule = rsPolicySpaceList[i]
        for j in range(0, i):
            cmpRule = rsPolicySpaceList[j]
            if not curRule.__and__(cmpRule): # curRule /\ cmpRule == None
                continue
            else:
                result[i,j] = result[j,i] = 1
    end = time.time()
    logger.info("The time runs for {total_time}s".format(total_time=end-start))
    return result


def getRuleMatOnDim(filename, dims=[0,1,2,3,4]):
    global logger
    rs = pc.load_rules(filename)
    start = time.time()
    logger.info("="*50)
    # Convert rules into the policyspace
    rsPolicySpaceList = []
    for r in rs:
        cur_rule = PolicySpace([HyperRect(deepcopy(r[:5]))])
        rsPolicySpaceList.append(cur_rule)
    ruleNum = len(rsPolicySpaceList)
    logger.info("Finish the PolicySpace Convert.")
    # init the matrix
    result = np.matlib.eye(n=ruleNum, dtype=int)
    for i in range(1, ruleNum):
        curRule = rsPolicySpaceList[i]
        for j in range(0, i):
            cmpRule = rsPolicySpaceList[j]
            if curRule.is_overlap(cmpRule, dims):
                result[i,j] = result[j,i] = 1
    end = time.time()
    logger.info("The time runs for {total_time}s".format(total_time=end-start))
    return result

# %% Run
ruleRootPath = os.path.join(".", "rules")
g = os.walk(ruleRootPath)
resMap = {}
for path, dir_list, file_list in g:
    for filename in file_list:
        filePath = os.path.join(ruleRootPath, filename)
# print(filePath)

# %% Get the All fields
for rulename in ['acl1_1K', 'fw1_1K', 'ipc1_1K']:
    mat = getRuleMat(os.path.join('.','rules', rulename))
    print("We have total edges: {edgenum:0.0f} with size: {MatSize}".format(edgenum=(mat.sum()-753)/2, MatSize=mat.shape))
    im = Image.fromarray(np.uint8(mat * 255))
    im.save(rulename+".png")
    im.show()

# %% Get the Specified fields
for rulename in ['acl1_1K', 'fw1_1K', 'ipc1_1K']:
    mat = getRuleMatOnDim(os.path.join('.','rules', rulename), [0,1,4])
    print("We have total edges: {edgenum:0.0f} with size: {MatSize}".format(edgenum=(mat.sum()-753)/2, MatSize=mat.shape))
    im = Image.fromarray(np.uint8(mat * 255))
    im.save(rulename+"_srcIP_dstIP_proto.png")
    im.show()


# %%

if False:
    # Graph 分析
    fw1=getRuleMat(os.path.join('.','rules','fw1_10K'))
    print("We have total edges: {edgenum:0.0f} with size: {MatSize}".format(edgenum=(fw1.sum()-753)/2, MatSize=fw1.shape))
    im2 = Image.fromarray(np.uint8(fw1 * 255))
    im2.show()
    
    G = nx.from_numpy_matrix(mat) # acl1Mat[0:-4, 0:-4]
    type(G)
    
    # acl1Mat[752,:]
    nx.diameter(G)
    print("density is {den:.2f}%".format(den =nx.density(G)*100) )
    
    nx.degree_histogram(G)
    len(nx.degree_histogram(G))
    
    d = nx.coloring.greedy_color(G, strategy="connected_sequential")
    Counter(d.values())
