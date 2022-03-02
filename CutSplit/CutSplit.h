#ifndef  _CUTSPLIT_H
#define  _CUTSPLIT_H

#define MAXDIMENSIONS 5
#define MAXBUCKETS 40
#define MAXNODES 500000
#define MAXRULES 1000000
#define MAXPACKETS 2000000 //to avoid segmentation fault, please change stack size to 81920 or larger, run "ulimit -s 81920"
#define MAXCUTS  16
#define PTR_SIZE 4
#define HEADER_SIZE 4
#define LEAF_NODE_SIZE 4
#define TREE_NODE_SIZE 8  

class range  
{
public:
   unsigned low;
   unsigned high;
};

class pc_rule
{
public:
    int id;
    range field[MAXDIMENSIONS];
};

class field_length
{
public:
unsigned length[5];
int size[5];
int flag_smallest[4]; 
};

class hs_result  //result of hypersplit tree
{
public:
int num_rules;
int num_childnode;
int wst_depth;
float avg_depth;
int num_tree_node;
int num_leaf_node;
float total_mem_kb;
};

#endif 
