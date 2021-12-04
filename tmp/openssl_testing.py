# remember to remove syscall column
import os
import math
import numpy as np
import pandas as pd

def heuristics(name2sign, df):
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    actual_matched = 0
    actual_nonmatched = 0
    np_df = df.to_numpy()
    for row in np_df:
        featsum = 0.0
        if row[-1] == True:
            actual_matched += 1
        else:
            actual_nonmatched += 1

        pred = False
        for i in row[1:5]:
            if i == 0:
                pred |= True

        for i in row[1:5]:
            if math.isnan(i):
                continue
            featsum += i
        name2sign[row[0]] = featsum

        if pred:
            if row[-1] == True:
                print("tp: " + row[0])
                tp += 1
            else:
                print("fp: " + row[0])
                fp += 1
        else:
            if row[-1] == False:
                tn += 1
            else:
                fn += 1
    print("tp: " + str(tp))
    print("fp: " + str(fp))
    name2sign = dict(sorted(name2sign.items(), key=lambda item: item[1]))
    return name2sign, (tp / actual_matched), (fp / actual_nonmatched)

def main():
    name2sign = {}
    template = '/home/rafael/Desktop/patched-openssl/apps/openssl'
    target = '/home/rafael/Desktop/unpatched-openssl/apps/openssl'
    function = 'EC_GROUP_new_from_ecparameters'
    # create vector.txt
    os.chdir('egalito-reversePatch/app/')
    cmd = './etharden --rev-patch ' + template + ' ' + target + ' ' + function + ' ' + 'CVE-2021-3712'
    #os.system(cmd)
    # create combined hamm.csv
    os.chdir('/home/rafael/Desktop/')
    cmd = 'python3 hi.py /home/rafael/Desktop/CVE-2021-3712/vector.txt '
    cmd += '/home/rafael/Desktop/CVE-2021-3712/hamm.csv '
    cmd += '/home/rafael/Desktop/CVE-2021-3712/jacc.csv'
    #os.system(cmd)
    # heuristics
    df = pd.read_csv('/home/rafael/Desktop/CVE-2021-3712/hamm.csv')
    df = df[['name', 'op', 'type', 'callee', 'plt', 'matched']]
    name2sign, tp_ratio, fp_ratio = heuristics(name2sign, df)
    print('tp score: ' + str(tp_ratio))
    print('fp score: ' + str(fp_ratio))
    cnt = 0
    for k, v in name2sign.items():
        if cnt > 10:
            break
        print(k)
        print(v)
        cnt += 1

main()
