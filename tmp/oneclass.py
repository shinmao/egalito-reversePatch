# before use this file, remember to discard syscall columns in combined csv first
import math
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import time
#import pandas_profiling
from sklearn.svm import OneClassSVM
import scipy.cluster.hierarchy as shc
from sklearn.cluster import AgglomerativeClustering
from sklearn.model_selection import train_test_split
from sklearn.metrics import f1_score
from sklearn.metrics import classification_report, recall_score

def svm(trainx, testx, trainy, testy):
    # trainset should not have outliers
    model = OneClassSVM(nu=0.1, kernel="rbf", gamma=0.1)
    # fit on majority class
    trainx = trainx[trainy == False]
    model.fit(trainx)
    # detect outliers in the test set
    yhat = model.predict(testx)
    # mark inliers and outliers
    testy[testy == True] = -1
    testy[testy == False] = 1
    # calculate F1 score
    score = f1_score(testy, yhat, pos_label = -1)
    #print("F1 score: %.3f" % score)
    #print(classification_report(testy, yhat, target_names=['matched', 'not matched']))
    return recall_score(testy, yhat, pos_label=-1)

def agglocluster(dataset, label):
    cluster = AgglomerativeClustering(n_clusters=2, affinity='euclidean', linkage='ward')
    res = cluster.fit_predict(dataset)
    tp = 0
    actual_matched = 0
    actual_nonmatched = 0
    for i in label:
        if i == True:
            actual_matched += 1
        else:
            actual_nonmatched += 1

    for pred, lab in zip(res, label):
        if (pred == 1) and (lab == True):
            tp += 1
    return tp / actual_matched

def lazymodel(name2sign, df):
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    actual_matched = 0
    actual_nonmatched = 0
    np_df = df.to_numpy()
    for row in np_df:
        feat_sum = 0.0
        if row[-1] == True:
            actual_matched += 1
        else:
            actual_nonmatched += 1

        pred = False
        for i in row[1:5]:
            if i == 0.0:
                print(row[1:4])
                pred |= True

        for i in row[1:5]:
            if math.isnan(i):
                continue
            feat_sum += i
        name2sign[row[0]] = feat_sum

        if pred:   # predict as True
            if row[-1] == True:
                print("tp: " + row[0])
                tp += 1
            else:
                print("fp: " + row[0])
                fp += 1
        else:     # predict as False
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
    dataset = "./combined_hamm_csv.csv"
    df = pd.read_csv(dataset)
    df_feat = df[["op", "type", "callee", "plt"]]
    df_class = df["matched"]
    svm_recall_score = 0.0
    #print(df_feat.to_numpy())
    #print(df_class.to_numpy())
    '''
    for i in range(200):
        trainx, testx, trainy, testy = train_test_split(df_feat, df_class)
        svm_recall_score += svm(trainx, testx, trainy, testy)
    svm_recall_score = svm_recall_score / 200.0
    print("average for svm recall score: {:.3f}".format(svm_recall_score))
    '''
    trainx, testx, trainy, testy = train_test_split(df_feat, df_class)
    start_time = time.time()
    print(svm(trainx, testx, trainy, testy))
    print("---%s seconds ---" % (time.time() - start_time))
    #print("To decide the clusters number.")
    #plt.figure(figsize=(10, 7))
    #plt.title("Dendrograms")
    #dend = shc.dendrogram(shc.linkage(df_feat, method='ward'))
    #plt.show()
    start_time = time.time()
    print(agglocluster(df_feat, df_class))
    print("---%s seconds ---" % (time.time() - start_time))
    start_time = time.time()
    name2sign, tp_act, fp_act = lazymodel(name2sign, df)
    print("---%s seconds ---" % (time.time() - start_time))
    print("Functions which are identified as target and truly is: " + str(tp_act))
    print("Functions which are identified as target but actually not: " + str(fp_act))
    for k, v in name2sign.items():
        if k[:6] == 'grep13':
            print(k)
            if 'grepfile/grepfile' in k:
                print('Congratttttttttttttttttttttttttttttts!')

main()
