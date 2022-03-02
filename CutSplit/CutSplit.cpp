/*-----------------------------------------------------------------------------
 *
 *  Name:		CutSplit.c
 *  Description:	CutSplit packet classification algorithm
 *  Version:		2.0 (release)
 *  Author:		Wenjun Li (Peking University, Email:wenjunli@pku.edu.cn)
 *  Date:		5/3/2019 (Today is my daughter(Yuhui Li)'s 3rd birthday. Wish her a happy birthday!)
 *
 *-----------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <list>
#include <cstring>
#include "CutSplit.h"
#include "hs.h"
#include "trie.h"
#include "common.h"
#include <sys/time.h>
#include "stdinc.h"
#include "hs_inner.h"

using namespace std;

struct timeval gStartTime, gEndTime;

int isNSLabFormat = 1;

FILE *fpr = fopen("./fw1_10k_CutSplit", "r"); // ruleset file
// FILE *fpr = fopen("./rules/acl1_100K","r");
FILE *fpt = fopen("./fw1_10k_trace", "r"); // test trace file
// FILE *fpt = NULL;
FILE *fpm = fopen("./fw1_10k_CutSplit.mark", "r");

int isMarkEnable = 1;

int bucketSize = 8; // leaf threashold
int threshold = 24; // Assume T_SA=T_DA=threshold

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  loadrule
 *  Description:  load rules from file
 * =====================================================================================
 */
int loadrule(FILE *fp, pc_rule *rule)
{
  int tmp;
  unsigned sip1, sip2, sip3, sip4, smask;
  unsigned dip1, dip2, dip3, dip4, dmask;
  unsigned sport1, sport2;
  unsigned dport1, dport2;
  unsigned protocal, protocol_mask;
  unsigned ht, htmask;
  int number_rule = 0; //number of rules

  int ignore;

  while (1)
  {
    // if(fscanf(fp,"@%d.%d.%d.%d/%d\t%d.%d.%d.%d/%d\t%d : %d\t%d : %d\t%x/%x\t%x/%x\n",
    //           &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &rule[number_rule].field[2].low, &rule[number_rule].field[2].high,
    //           &rule[number_rule].field[3].low, &rule[number_rule].field[3].high,&protocal, &protocol_mask, &ht, &htmask)!= 18) {
    //           break;
    //         }
    // if(fscanf(fp,"@%d.%d.%d.%d/%d %d.%d.%d.%d/%d %d : %d %d : %d %x/%x %d\n",
    //     &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &rule[number_rule].field[2].low, &rule[number_rule].field[2].high,
    //     &rule[number_rule].field[3].low, &rule[number_rule].field[3].high, &protocal, &protocol_mask, &ignore) != 17) {
    //     break;
    // }
    if (isNSLabFormat == 1)
    {
      if (fscanf(fp, "@%d.%d.%d.%d/%d %d.%d.%d.%d/%d %d : %d %d : %d %x/%x\n",
                 &sip1, &sip2, &sip3, &sip4, &smask, &dip1, &dip2, &dip3, &dip4, &dmask, &rule[number_rule].field[2].low, &rule[number_rule].field[2].high,
                 &rule[number_rule].field[3].low, &rule[number_rule].field[3].high, &protocal, &protocol_mask) != 16)
      {
        printf("!!scanf fails for the rule file.\n");
        break;
      }

    }

    if (smask == 0)
    {
      rule[number_rule].field[0].low = 0;
      rule[number_rule].field[0].high = 0xFFFFFFFF;
    }
    else if (smask > 0 && smask <= 8)
    {
      tmp = sip1 << 24;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1 << (32 - smask)) - 1;
    }
    else if (smask > 8 && smask <= 16)
    {
      tmp = sip1 << 24;
      tmp += sip2 << 16;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1 << (32 - smask)) - 1;
    }
    else if (smask > 16 && smask <= 24)
    {
      tmp = sip1 << 24;
      tmp += sip2 << 16;
      tmp += sip3 << 8;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1 << (32 - smask)) - 1;
    }
    else if (smask > 24 && smask <= 32)
    {
      tmp = sip1 << 24;
      tmp += sip2 << 16;
      tmp += sip3 << 8;
      tmp += sip4;
      rule[number_rule].field[0].low = tmp;
      rule[number_rule].field[0].high = rule[number_rule].field[0].low + (1 << (32 - smask)) - 1;
    }
    else
    {
      printf("Src IP length (%u) exceeds 32 at %d-th rule\n", smask, number_rule);
      return 0;
    }
    if (dmask == 0)
    {
      rule[number_rule].field[1].low = 0;
      rule[number_rule].field[1].high = 0xFFFFFFFF;
    }
    else if (dmask > 0 && dmask <= 8)
    {
      tmp = dip1 << 24;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1 << (32 - dmask)) - 1;
    }
    else if (dmask > 8 && dmask <= 16)
    {
      tmp = dip1 << 24;
      tmp += dip2 << 16;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1 << (32 - dmask)) - 1;
    }
    else if (dmask > 16 && dmask <= 24)
    {
      tmp = dip1 << 24;
      tmp += dip2 << 16;
      tmp += dip3 << 8;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1 << (32 - dmask)) - 1;
    }
    else if (dmask > 24 && dmask <= 32)
    {
      tmp = dip1 << 24;
      tmp += dip2 << 16;
      tmp += dip3 << 8;
      tmp += dip4;
      rule[number_rule].field[1].low = tmp;
      rule[number_rule].field[1].high = rule[number_rule].field[1].low + (1 << (32 - dmask)) - 1;
    }
    else
    {
      printf("Dest IP length exceeds 32\n");
      return 0;
    }
    if (protocol_mask == 0xFF)
    {
      rule[number_rule].field[4].low = protocal;
      rule[number_rule].field[4].high = protocal;
    }
    else if (protocol_mask == 0)
    {
      rule[number_rule].field[4].low = 0;
      rule[number_rule].field[4].high = 0xFF;
    }
    else
    {
      printf("Protocol mask error\n");
      return 0;
    }

    rule[number_rule].id = number_rule;
    number_rule++;
  }

  /*
   printf("the number of rules = %d\n", number_rule);
     for(int i=0;i<number_rule;i++){
      printf("%u: %u:%u %u:%u %u:%u %u:%u %u:%u\n", i,
        rule[i].field[0].low, rule[i].field[0].high,
        rule[i].field[1].low, rule[i].field[1].high,
        rule[i].field[2].low, rule[i].field[2].high,
        rule[i].field[3].low, rule[i].field[3].high,
        rule[i].field[4].low, rule[i].field[4].high);}
   */

  return number_rule;
}

void parseargs(int argc, char *argv[])
{
  int c;
  bool ok = 1;
  while ((c = getopt(argc, argv, "b:t:r:e:m:s:h")) != -1)
  {
    switch (c)
    {
    case 'b':
      bucketSize = atoi(optarg);
      break;
    case 't':
      threshold = atoi(optarg);
      break;
    case 'r':
      fclose(fpr);
      fpr = fopen(optarg, "r");
      break;
    case 'e':
      fclose(fpt);
      fpt = fopen(optarg, "r");
      break;
    case 'm':
      fclose(fpm);
      fpm = fopen(optarg, "r");
      break;
    case 's':
    // State, enable PCG or not
      isMarkEnable = atoi(optarg);
      break;
    case 'h':
      printf("CutSplit [-b bucketSize][-t threshold(assume T_SA=T_DA)][-r ruleset][-e trace][-m markset]\n");
      printf("mail me: wenjunli@pku.edu.cn. Some codes are modified by chengjunjia1997@qq.com\n");
      exit(1);
      break;
    default:
      ok = 0;
    }
  }

  if (bucketSize <= 0 || bucketSize > MAXBUCKETS)
  {
    printf("bucketSize should be greater than 0 and less than %d\n", MAXBUCKETS);
    ok = 0;
  }
  if (threshold < 0 || threshold > 32)
  {
    printf("threshold should be greater than 0 and less than 32\n");
    ok = 0;
  }
  if (fpr == NULL)
  {
    printf("can't open ruleset file\n");
    ok = 0;
  }
  if (!ok || optind < argc)
  {
    fprintf(stderr, "CutSplit [-b bucketSize][-t threshold(assume T_SA=T_DA)][-r ruleset][-e trace]\n");
    fprintf(stderr, "Type \"CutSplit -h\" for help\n");
    exit(1);
  }

  printf("************CutSplit: version 2.0 (add trace fuction)******************\n");
  printf("Bucket Size =  %d\n", bucketSize);
  printf("Threshold = %d,%d\n", threshold, threshold);
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  dump_rule
 *  Description:  dump rules or rule set, for testing
 * =====================================================================================
 */
void dump_rule(pc_rule *rule, int rule_id)
{
  int i;
  pc_rule *p = &rule[rule_id];
  range r;

  printf("rule[%d]:\t", rule_id);

  // dump SIP & DIP
  for (i = 0; i < 2; i++)
  {
    r = p->field[i];
    if (r.low == r.high)
      dump_ip(r.low);
    else if (r.low == 0 && r.high == 0xffffffff)
      printf("*");
    else
    {
      dump_ip(r.low);
      printf("/%d", log2(r.high - r.low + 1));
    }
    printf(",\t");
  }

  // dump SP & DP
  for (i = 2; i < 4; i++)
  {
    r = p->field[i];
    if (r.low == r.high)
      printf("%x", r.low);
    else if (r.low == 0 && r.high == 0xffff)
      printf("*");
    else
    {
      printf("[%x-%x]", r.low, r.high);
    }
    printf(",  ");
  }

  // dump proto
  r = p->field[4];
  if (r.low == r.high)
    printf("%d", r.low);
  else if (r.low == 0 && r.high == 0xff)
    printf("*");
  else
    printf("[%d-%d]", r.low, r.high);

  printf("\n");
}

void dump_ruleset(pc_rule *rule, int num)
{
  for (int i = 0; i < num; i++)
    dump_rule(rule, i);
  printf("\n");
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  count_length
 *  Description:  record length of field and correponding size
 * =====================================================================================
 */
void count_length(int number_rule, pc_rule *rule, field_length *field_length_ruleset)
{
  unsigned temp_size = 0;
  unsigned temp_value = 0;
  //unsigned temp0=0;

  for (int i = 0; i < number_rule; i++)
  {
    for (int j = 0; j < 5; j++) //record field length in field_length_ruleset[i]
    {
      field_length_ruleset[i].length[j] = rule[i].field[j].high - rule[i].field[j].low;
      if (field_length_ruleset[i].length[j] == 0xffffffff)
        field_length_ruleset[i].size[j] = 32; //for address *
      else
      {
        temp_size = 0;
        temp_value = field_length_ruleset[i].length[j] + 1;
        while ((temp_value = temp_value / 2) != 0)
          temp_size++;
        //for port number
        if ((field_length_ruleset[i].length[j] + 1 - pow(2, temp_size)) != 0)
          temp_size++;

        field_length_ruleset[i].size[j] = temp_size;
      }
    }
  }
}

/*
 * ===  FUNCTION  ======================================================================
 *         Name:  partition_v1 (version1)
 *  Description:  partition ruleset into subsets based on address field(2 dim.)
 * =====================================================================================
 */
void partition_v1(pc_rule *rule, pc_rule *subset[3], int num_subset[3], int number_rule, field_length *field_length_ruleset, int threshold_value[2])
{
  static int num_small_tmp[MAXRULES];
  for (int i = 0; i < number_rule; i++)
  {
    num_small_tmp[i] = 0;
    for (int k = 0; k < 2; k++)
      if (field_length_ruleset[i].size[k] <= threshold_value[k])
        num_small_tmp[i]++;
  }

  int count_big = 0;
  for (int i = 0; i < number_rule; i++)
    if (num_small_tmp[i] == 0)
      subset[0][count_big++] = rule[i];
  num_subset[0] = count_big;

  int count_sa = 0;
  int count_da = 0;
  for (int i = 0; i < number_rule; i++)
  {
    if ((num_small_tmp[i] == 1) && (field_length_ruleset[i].size[0] <= threshold_value[0]))
      subset[1][count_sa++] = rule[i];
    if ((num_small_tmp[i] == 1) && (field_length_ruleset[i].size[1] <= threshold_value[1]))
      subset[2][count_da++] = rule[i];

    if (num_small_tmp[i] == 2)
    {
      if (field_length_ruleset[i].size[0] < field_length_ruleset[i].size[1])
        subset[1][count_sa++] = rule[i];
      else if (field_length_ruleset[i].size[0] > field_length_ruleset[i].size[1])
        subset[2][count_da++] = rule[i];
      else if (count_sa <= count_da)
        subset[1][count_sa++] = rule[i];
      else
        subset[2][count_da++] = rule[i];
    }
  }

  num_subset[1] = count_sa;
  num_subset[2] = count_da;
  printf("Big_subset:%d\tSa_subset:%d\tDa_subset:%d\n\n", count_big, count_sa, count_da);

  /*
   printf("***********************big_ruleset*******************************************\n");
        if(num_subset[0]!=0)
           dump_ruleset(subset[0],num_subset[0]);
        else
           printf("empty!\n");
   printf("***********************SA_ruleset********************************************\n");
        dump_ruleset(subset[1],num_subset[1]);
   printf("***********************DA_ruleset********************************************\n");
        dump_ruleset(subset[2],num_subset[2]);
*/
}

int HSmain(int argc, char *argv[])
{
  // CutSplitMain(argc, argv);
  pc_rule *rule;
  int number_rule = 0;
  printf("Start the main program\n");
  parseargs(argc, argv);

  char test1;
  while ((test1 = fgetc(fpr)) != EOF)
    if (test1 == '@')
      number_rule++;
  rewind(fpr);

  rule = (pc_rule *)calloc(number_rule, sizeof(pc_rule));
  number_rule = loadrule(fpr, rule);
  printf("the number of rules = %d\n", number_rule);
  fclose(fpr);

  gettimeofday(&gStartTime, NULL);
  hs_node_t *big_node = (hs_node_t *)malloc(sizeof(hs_node_t));
  hstrie T(number_rule, rule, bucketSize, big_node);
  printf("***Big rules(using HyperSlit):***\n");
  printf(">>RESULTS:");
  printf("\n>>number of rules: %d", T.result.num_rules);
  printf("\n>>number of children: %d", T.result.num_childnode);
  printf("\n>>worst case tree depth: %d", T.result.wst_depth);
  printf("\n>>average tree depth: %f", T.result.avg_depth);
  printf("\n>>number of tree nodes:%d", T.result.num_tree_node);
  printf("\n>>number of leaf nodes:%d", T.result.num_leaf_node);
  printf("\n>>total memory: %f(KB)", T.result.total_mem_kb);
  printf("\n***SUCCESS in building HyperSplit sub-tree for big rules***\n\n");
  gettimeofday(&gEndTime, NULL);
  printf("***Total preprocessing time: %ld(ms)\n", 1000 * (gEndTime.tv_sec - gStartTime.tv_sec) + (gEndTime.tv_usec - gStartTime.tv_usec) / 1000);
}

int main(int argc, char *argv[])
{
  pc_rule *rule;
  int number_rule = 0;
  printf("Start the main program\n");
  parseargs(argc, argv);

  char test1;
  while ((test1 = fgetc(fpr)) != EOF)
    if (test1 == '@')
      number_rule++;
  rewind(fpr);

  rule = (pc_rule *)calloc(number_rule, sizeof(pc_rule));
  number_rule = loadrule(fpr, rule);
  printf("the number of rules = %d\n", number_rule);
  fclose(fpr);
  field_length *field_length_ruleset = (field_length *)calloc(number_rule, sizeof(field_length));
  count_length(number_rule, rule, field_length_ruleset);

  pc_rule *subset_3[3];
  for (int n = 0; n < 3; n++)
    subset_3[n] = (pc_rule *)malloc(number_rule * sizeof(pc_rule));
  int num_subset_3[3] = {0, 0, 0};
  int threshold_value_3[2] = {threshold, threshold};

  printf("Start to partition\n");
  partition_v1(rule, subset_3, num_subset_3, number_rule, field_length_ruleset, threshold_value_3);

  printf("\n num_sa = %d   num_da = %d   num_big = %d \n", num_subset_3[1], num_subset_3[2], num_subset_3[0]);

  gettimeofday(&gStartTime, NULL);

  trie T_sa(num_subset_3[1], bucketSize, rule, subset_3[1], threshold, 0);
  trie T_da(num_subset_3[2], bucketSize, rule, subset_3[2], threshold, 1);

  // dump_ruleset(subset_3[0],num_subset_3[0]);

  hs_node_t *big_node = (hs_node_t *)malloc(sizeof(hs_node_t));
  if (num_subset_3[0] > 0)
  {
    hstrie T(num_subset_3[0], subset_3[0], bucketSize, big_node);
    printf("***Big rules(using HyperSlit):***\n");
    printf(">>RESULTS for bucket(%d):", bucketSize);
    printf("\n>>number of rules: %d", T.result.num_rules);
    printf("\n>>number of children: %d", T.result.num_childnode);
    printf("\n>>worst case tree depth: %d", T.result.wst_depth);
    printf("\n>>average tree depth: %f", T.result.avg_depth);
    printf("\n>>number of tree nodes:%d", T.result.num_tree_node);
    printf("\n>>number of leaf nodes:%d", T.result.num_leaf_node);
    printf("\n>>total memory: %f(KB)", T.result.total_mem_kb);
    printf("\n***SUCCESS in building HyperSplit sub-tree for big rules***\n\n");
    // T.trace_leaf(big_node);
    /*
    hstrieInner Tn(num_subset_3[0],subset_3[0], bucketSize, big_node);
    printf("***Big rules(using HyperSlit-New):***\n");
    printf(">>RESULTS for bucket(%d):", bucketSize);
    printf("\n>>number of rules: %d", Tn.result.num_rules);
    printf("\n>>number of children: %d", Tn.result.num_childnode);
    printf("\n>>worst case tree depth: %d", Tn.result.wst_depth);
    printf("\n>>average tree depth: %f", Tn.result.avg_depth);
    printf("\n>>number of tree nodes:%d", Tn.result.num_tree_node);
    printf("\n>>number of leaf nodes:%d", Tn.result.num_leaf_node);
    printf("\n>>total memory: %f(KB)", Tn.result.total_mem_kb);
    printf("\n***SUCCESS in building HyperSplit sub-tree for big rules***\n\n");
*/
  }

  gettimeofday(&gEndTime, NULL);
  printf("***Total preprocessing time: %ld(ms)\n", 1000 * (gEndTime.tv_sec - gStartTime.tv_sec) + (gEndTime.tv_usec - gStartTime.tv_usec) / 1000);

  // int **header = (int**)calloc(MAXPACKETS, sizeof(int*));
  // for (int i = 0 ; i < MAXPACKETS; i++) {
  //   header[i] = (int*) calloc(MAXDIMENSIONS, sizeof(int));
  // }
  static int header[MAXPACKETS][MAXDIMENSIONS];
  int match_sa, match_da, match_big, fid[MAXPACKETS];
  int matchid;
  unsigned int proto_mask;

  if (fpt != NULL)
  {
    int number_pkt = 0, match_miss = 0;
    // Original file format
    // while ( fscanf(fpt, "%u %u %d %d %d %u %d\n",
    //               &header[number_pkt][0], &header[number_pkt][1], &header[number_pkt][2], &header[number_pkt][3], &header[number_pkt][4], &proto_mask, &fid[number_pkt]) != Null )
    // {
    //   number_pkt++;
    // }

    // Self format
    while ( fscanf(fpt, "%u %u %d %d %d %d\n",
                  &header[number_pkt][0], &header[number_pkt][1], &header[number_pkt][2], &header[number_pkt][3], &header[number_pkt][4], &fid[number_pkt]) != Null )
    {
      fid[number_pkt]--; // TODO: for our format, the fid starts from 1
      number_pkt++;
    }


    int markNo = 0;
    FILE *fMark = fpm;
    static int markList[20000];
    memset(markList, 0, sizeof(int)*20*1000);
    if (fMark != NULL && isMarkEnable == 1)
    {
      while (fscanf(fMark, "%d\n", &markList[markNo]) != Null)
      {
        markNo++;
      }
    }
    printf("\n\nRead the mark total: %d\n", markNo);

    int srcSkipNum = 0;
    int dstSkipNum = 0;
    gettimeofday(&gStartTime, NULL);
    for (int k = 0; k < number_pkt; k++)
    {
      //printf("\n>> packet %d\n", k+1);
      matchid = match_sa = match_da = match_big = -1;

      //int header1[MAXDIMENSIONS];
      //for(int m=0;m<MAXDIMENSIONS;m++) header1[m]=header[k][m];

      match_sa = T_sa.trieLookup(header[k]);
      printf("Get the src match result: %d\n",match_sa);
      if (match_sa != -1 && markList[match_sa] == 1)
      {
        srcSkipNum++;
        matchid = match_sa;
        goto CLASSEND;
      }
      match_da = T_da.trieLookup(header[k]);
      printf("Get the dst match result: %d\n",match_da);
      if (match_da != -1 && markList[match_da] == 1)
      {
        dstSkipNum++;
        matchid = match_da;
        goto CLASSEND;
      }
      if (num_subset_3[0] > 0)
        match_big = LookupHSTree(rule, big_node, header[k]);

      printf("Get the big match result: %d\n", match_big);
      // if (k == 692) {
      //    printf("\nmatch_sa = %d   match_da = %d   match_big = %d with big: %d\n", match_sa, match_da, match_big, num_subset_3[0]);
      // }

      if (match_sa != -1)
        matchid = match_sa;
      if ((matchid == -1) || (match_da != -1 && match_da < matchid))
        matchid = match_da;
      if ((matchid == -1) || (match_big != -1 && match_big < matchid))
        matchid = match_big;
      //printf("match_id = %d   fid = %d\n", matchid, fid[k]);

    CLASSEND:
      if (matchid == -1)
      {
        // TODO: debug for the matchid==-1 (For some cases, the result is here?)
        // printf("? packet %d match NO rule, should be %d\n", k, fid[k]);
        // match_miss++;
      }
      else if (matchid == fid[k])
      {
        //printf("\nmatch_id = %d   fid = %d   -----   packet %d match rule %d\n", matchid, fid[k], i, matchid);
      }
      else if (matchid > fid[k])
      {
        printf("? packet %d match lower priority rule %d, should be %d\n", k, matchid, fid[k]);
        match_miss++;
      }
      else
      {
        match_miss++;
        printf("! packet %d match higher priority rule %d, should be %d\n", k, matchid, fid[k]);
      }
    }
    gettimeofday(&gEndTime, NULL);
    printf("***Total classification time: %ld(us)\n", 1000 * 1000 * (gEndTime.tv_sec - gStartTime.tv_sec) + (gEndTime.tv_usec - gStartTime.tv_usec) );
    printf("\n%d packets are classified, %d of them are misclassified\n\n", number_pkt, match_miss);
    printf("Source skip is %d and dst Skip is %d\n", srcSkipNum, dstSkipNum);
  }
  else
  {
    printf("\nNo packet trace input\n");
  }
}
