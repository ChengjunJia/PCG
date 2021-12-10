# PCG
Packet Classification Group

## PSA
利用PSA分析规则集特性, 得出哪些规则是top的无交叠规则, 并记录相关结果。
main.py是分析脚本，结果保存到res.npy文件中；loadResult.py加载npy文件，以便得出相关结果。

使用drawMat.py脚本绘制规则之间的关系图(如果两个规则之间存在交叠，则进行连线)，然后对图进行染色处理。
在policyspace.py中增加is_overlap的判断; 来进行自定义的域交叠判断。如果两个规则之间任意一个field存在交叠，进行连线。

从drawMat.py可以绘制出规则的邻接矩阵情况。