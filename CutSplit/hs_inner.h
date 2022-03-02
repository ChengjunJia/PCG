#include "CutSplit.h"
#include "hs.h"

#ifndef  _HS_INNER_H
#define  _HS_INNER_H

class hstrieInner {

public:
unsigned int	binth;
unsigned int	gChildCount;
unsigned int	gNumTreeNode;
unsigned int	gNumLeafNode;
unsigned int	gWstDepth;
unsigned int	gAvgDepth;
unsigned int	gNumNonOverlappings[DIM];
unsigned long long	gNumTotalNonOverlappings;
hs_result result;

public:

hstrieInner(int number, pc_rule* subset, int binth, hs_node_t* node);

/* build hyper-split-tree */
int BuildHSTree(rule_set_t* ruleset, hs_node_t* node, unsigned int depth); /* main */

};

#endif 
