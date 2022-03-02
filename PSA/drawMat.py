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

# init logger
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
        
        fh = logging.FileHandler('main.log')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        
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
# for rulename in ['acl1_1K', 'fw1_1K', 'ipc1_1K']:
for tup in [[0], [0,1], [0,1,4]]:
    rulename = "fw1_10K"
    mat = getRuleMatOnDim(os.path.join('.','rules', rulename), tup)
    print("We have total edges: {edgenum:0.0f} with size: {MatSize}".format(edgenum=(mat.sum()-753)/2, MatSize=mat.shape))
    logger.info("We have total edges: {edgenum:0.0f} -> {newedge:0.0f}  with size: {MatSize} for the {rule} with {tup}".format(edgenum=(mat.sum()-mat.shape[0])/2, newedge=(mat.sum()-mat.shape[0])/2-mat.shape[0], MatSize=mat.shape, rule=rulename, tup =tup))
    G = nx.from_numpy_matrix(mat) # acl1Mat[0:-4, 0:-4]
    # acl1Mat[752,:]
    degreeRes = nx.degree_histogram(G)

    logger.info("density is {den:.2f}%".format(den =nx.density(G)*100) )
    logger.info("degree is {deg}".format(deg=Counter(degreeRes)))
    
    color = nx.coloring.greedy_color(G, strategy="connected_sequential")
    colRes = Counter(color.values())
    logger.info( "size: {colorNum}/{colorSize} and list: {colorList}" .format( colorSize=colRes, colorNum = len(colRes), colorList = color ) )
    logger.info("===================================")
    # im = Image.fromarray(np.uint8(mat * 255))
    # im.save(rulename+"_srcIP_dstIP_proto.png")
    # im.show()
    


# %%

for rulename in ['acl1_1K', 'fw1_1K', 'ipc1_1K', 'acl1_10K', 'fw1_10K', 'ipc1_10K']:
    mat = getRuleMat(os.path.join('.','rules', rulename))
    logger.info("We have total edges: {edgenum:0.0f} -> {newedge:0.0f}  with size: {MatSize} for the {rule}".format(edgenum=(mat.sum()-mat.shape[0])/2, newedge=(mat.sum()-mat.shape[0])/2-mat.shape[0], MatSize=mat.shape, rule=rulename))
    
    G = nx.from_numpy_matrix(mat) # acl1Mat[0:-4, 0:-4]
    # acl1Mat[752,:]
    degreeRes = nx.degree_histogram(G)

    logger.info("density is {den:.2f}%".format(den =nx.density(G)*100) )
    logger.info("degree is {deg}".format(deg=Counter(degreeRes)))
    
    color = nx.coloring.greedy_color(G, strategy="connected_sequential")
    logger.info( "size: {colorSize} and list: {colorList}" .format( colorSize=Counter(color.values()), colorList = color ) )
    logger.info("===================================")