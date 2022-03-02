# PCG

Packet Classification Group

论文见[paper](./PCG_paper.pdf)

TSS算法为了避免每次查找都需要遍历所有元组，使用如下加速方法：

1. 元组优先级定义为**组内规则最高优先级**
2. 元组按照元组优先级降序排序(高优先级优先)
3. 网包查找规则的过程中，依次查找各个元组，找到命中规则
4. 如果命中规则的优先级比后面的元组优先级更高，则不需要往后查找其他元组，直接输出结果

这种设计是因为"网包分类"是在找**命中的所有规则**中的**最高优先级**的那条规则(几乎所有规则集都有default规则,所有网包都可以命中该规则)。

根据我们使用PSA对规则集的分析，发现多数规则位于顶层(我们称该规则具有top特性)，规则占比达到60%-80%。换言之，将该规则调整到规则集中的最高优先级，并不会影响规则集查找结果的正确性。
如果一条规则是top，那么，如果网包命中该规则，规则集的查找最终结果也必然为该规则；无需通过比较其他规则来判断优先级大小。

基于以上观察，因此我们可以预先分析规则集，对顶层规则做单独标记。这样各种**基于分组**的网包分类**软件**算法都可以达到加速的效果。
根据对CutSplit的分析(源码见[目录](./CutSplit/))，平均吞吐可以提升20%左右(CutSplit只把规则分成了3组，所以提升没有那么明显；如果分组更多，则性能提升理论上更多一些，平均意义上最多能到50%)。
规则和对应规则生成的网包路径位于[该目录](./PSA/pc_plat/rule_trace)目录下。

## 进一步工作

## PSA

利用PSA分析规则集特性, 得出哪些规则是top的无交叠规则, 并记录相关结果。
main.py是分析脚本，结果保存到res.npy文件中；loadResult.py加载npy文件，以便得出相关结果。

使用drawMat.py脚本绘制规则之间的关系图(如果两个规则之间存在交叠，则进行连线)，然后对图进行染色处理。
在policyspace.py中增加is_overlap的判断; 来进行自定义的域交叠判断。如果两个规则之间任意一个field存在交叠，进行连线。

从drawMat.py可以绘制出规则的邻接矩阵情况。
