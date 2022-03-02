import os

os.system("make")
os.system('echo "=====================================================" >> out.log')

ruleList = ["acl1_1K", "fw1_1K", "ipc1_1K", "acl1_10K", "fw1_10K", "ipc1_10K"]
for r in ruleList:
    os.system("echo '--- File: {f}, origin---' >> out_origin.log".format(f=r))
    cmd1 = "./CutSplit -r ./rules/{rule} -e ./trace/{rule}_trace -m ./mark/{rule}.mark -s 0 >> out_origin.log".format(rule=r)
    os.system(cmd1)
for r in ruleList:
    os.system("echo '--- File: {f}, PCG ---' >> out_PCG.log".format(f=r))
    cmd2 = "./CutSplit -r ./rules/{rule} -e ./trace/{rule}_trace -m ./mark/{rule}.mark -s 1 >> out_PCG.log".format(rule=r)
    os.system(cmd2)
