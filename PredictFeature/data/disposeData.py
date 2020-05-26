# coding=utf-8
import sys
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

import csv
from GenerateModel import type
import numpy as np
import pandas as pd


# attackMap = set()
# with open("KDDTrain+.csv", "r") as f:
#     reader = csv.reader(f)
#     i = 0
#     for row in reader:
#         if i != 0:
#             attackMap.add(row[41])
#         i += 1
#
# with open("KDDTest+.csv", "r") as f:
#     reader = csv.reader(f)
#     i = 0
#     for row in reader:
#         if i != 0:
#             attackMap.add(row[41])
#         i += 1
#
# print(len(attackMap))
# i = 1
# for x in attackMap:
#     print('"'+x+'":'+str(i)+",")
#     if x!="normal":
#         i+=1


def disposeKDDData(readName, writerName):
    wf = open(writerName, "w", newline="")
    writerCSV = csv.writer(wf)
    # 0 1 2 3 4 5 6 7 8 22-40 41
    with open(readName, "r") as rf:
        reader = csv.reader(rf)
        i = 0
        for row in reader:
            if i == 0:
                line = []
                line.extend(row[0:9])
                line.extend(row[22:42])
                writerCSV.writerow(line)
            elif (row[41] in type.Attack.U2R) or (row[41] in type.Attack.R2L):
                continue
            else:
                line = []
                line.extend(row[0:9])
                line.extend(row[22:41])
                if row[41]=="normal":
                    line.append("normal")
                else:
                    line.append("attack")

                writerCSV.writerow(line)

            i += 1

    wf.close()


def disposeData(readName, writeName):
    wf = open(writeName, "w", newline="")
    writerCSV = csv.writer(wf)
    # 0 1 2 3 4 5 6 7 8 22-40 41
    with open(readName, "r") as rf:
        reader = csv.reader(rf)

        # 1 2 3 4 15 19 20 21 25 28
        # 1 2 3 4 12 14 15 20 21 25 27 28
        for row in reader:
            line = []
            # line.append(row[1])
            # line.append(row[2])
            # line.append(row[3])
            # line.append(row[4])
            # line.append(row[15])
            # line.append(row[19])
            # line.append(row[20])
            # line.append(row[21])
            # line.append(row[25])
            # line.append(row[28])

            line.append(row[0])
            line.append(row[1])
            line.append(row[2])
            line.append(row[3])
            line.append(row[4])
            line.append(row[5])
            line.append(row[12])
            line.append(row[14])
            line.append(row[15])
            line.append(row[16])
            line.append(row[20])
            line.append(row[21])
            line.append(row[25])
            line.append(row[27])
            line.append(row[28])
            writerCSV.writerow(line)

    wf.close()


def standardize(x):
    return (x - np.mean(x)) / (np.std(x))


def normalize(x):
    return (x - np.min(x)) / (np.max(x) - np.min(x))


def disposeNormalize(readName, wirteName):
    # reader = pd.read_csv(readName)
    #
    # src_bytes = reader['src_bytes']
    # src_bytes = np.array(src_bytes)
    # src_bytes = normalize(src_bytes)
    # reader['src_bytes'] = src_bytes

    # dst_host_srv_count = reader['dst_host_srv_count']
    # dst_host_srv_count = np.array(dst_host_srv_count)
    # dst_host_srv_count = normalize(dst_host_srv_count)
    # reader['dst_host_srv_count'] = dst_host_srv_count

    # reader.to_csv(wirteName,index = False)

    wf = open(wirteName, "w", newline="")
    writerCSV = csv.writer(wf)
    # 0 1 2 3 4 5 6 7 8 22-40 41
    with open(readName, "r") as rf:
        reader = csv.reader(rf)

        i = 1
        for row in reader:
            if i == 1:
                writerCSV.writerow(row)
                i += 1
                continue

            line = []
            # line.append(float(row[0]) / 58329)
            line.extend(row[0:4])
            line.append(float(row[4])/1379963888)
            line.append(float(row[5])/1309937401)
            line.extend(row[6:])
            # line.extend(row[0:3])
            # temp = float(row[3])/1379963888
            # line.append(temp)
            # line.append(row[4])
            # # temp = float(row[5])/255
            # temp = row[5]
            # line.append(temp)
            # line.extend(row[6:len(row)])
            writerCSV.writerow(line)

    wf.close()


if __name__ == "__main__":
    disposeKDDData("KDDTest+.csv", "FlowTest.csv")
    disposeKDDData("KDDTrain+.csv", "FlowTrain.csv")
    disposeData("FlowTest.csv", "RightTest.csv")
    disposeData("FlowTrain.csv", "RightTrain.csv")
    #disposeNormalize("RightTest.csv", "normalizeTest.csv")
    #disposeNormalize("RightTrain.csv", "normalizeTrain.csv")
