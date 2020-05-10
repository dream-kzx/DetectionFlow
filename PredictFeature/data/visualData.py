# coding=utf-8

# -*- coding: utf-8 -*-
import matplotlib.pyplot as plt
import csv
import numpy as np
from matplotlib.ticker import MultipleLocator

from GenerateModel import type as attackType

# name_list = ['Monday', 'Tuesday', 'Friday', 'Sunday']
# num_list = [1.5, 0.6, 7.8, 6]
# num_list1 = [1, 2, 3, 1]
# x = list(range(len(num_list)))
# total_width, n = 0.8, 2
# width = total_width / n
#
# plt.bar(x, num_list, width=width, label='boy', fc='y')
# for i in range(len(x)):
#     x[i] = x[i] + width
# plt.bar(x, num_list1, width=width, label='girl', tick_label=name_list, fc='r')
# plt.legend()
# plt.show()

label = ["duration", "protocol_type", "service", "flag", "src_bytes",
         "dst_bytes", "land", "wrong_fragment", "urgent", "count", "srv_count", "serror_rate",
         "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
         "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
         "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
         "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
         "dst_host_srv_rerror_rate", "label"]



class VisualData:
    def __init__(self):
        self.data = [[] for i in range(29)]
        self.set = []
        self.type = []
        self.graph_index = 1
        # self.duration = []
        # self.protocol_type = []
        # self.service = []
        # self.flag = []
        # self.src_bytes = []
        # self.dst_bytes = []
        # self.land = []
        # self.wrong_fragment = []
        # self.urgent = []
        # self.count = []
        # self.srv_count = []
        # self.serror_rate = []
        # self.srv_serror_rate = []
        # self.rerror_rate = []
        # self.srv_rerror_rate = []
        # self.same_srv_rate = []
        # self.diff_srv_rate = []
        # self.srv_diff_host_rate = []
        # self.dst_host_count = []
        # self.dst_host_srv_count = []
        # self.dst_host_same_srv_rate = []
        # self.dst_host_diff_srv_rate = []
        # self.dst_host_same_src_port_rate = []
        # self.dst_host_srv_diff_host_rate = []
        # self.dst_host_serror_rate = []
        # self.dst_host_srv_serror_rate = []
        # self.dst_host_rerror_rate = []
        # self.dst_host_srv_rerror_rate = []
        # self.label = []

    def loadFile(self, fileName):
        with open(fileName, "r") as f:
            reader = csv.reader(f)
            i = 0
            for row in reader:
                if i == 0:
                    i += 1
                    continue
                for i in range(29):
                    self.data[i].append(row[i])

    def dataToSet(self):
        for i in range(29):
            self.set.append(set(self.data[i]))
        colors = ['b', 'g', 'r']

        for value in self.data[28]:
            if value in attackType.Attack.DOS:
                self.type.append(colors[0])
            elif value in attackType.Attack.PROBE:
                self.type.append(colors[1])
            else:
                self.type.append(colors[2])

    # def visualContinucus(self, feature_index, interval, max_value):
    #
    #     dosList = [0 for i in range(interval)]
    #     probeList = [0 for i in range(interval)]
    #     normalList = [0 for i in range(interval)]
    #
    #     length = len(self.data[0])
    #     for i in range(length):
    #         value = float(self.data[feature_index][i])
    #         if self.data[28][i] in attackType.Attack.PROBE:
    #             for j in range(1, interval + 1):
    #                 if j == interval:
    #                     probeList[j - 1] += 1
    #                 if value < (max_value * j / float(interval)):
    #                     probeList[j - 1] += 1
    #                     break
    #         elif self.data[28][i] in attackType.Attack.DOS:
    #             for j in range(1, interval + 1):
    #                 if j == interval:
    #                     dosList[j - 1] += 1
    #                 if value < (max_value * j / float(interval)):
    #                     dosList[j - 1] += 1
    #                     break
    #         else:
    #             for j in range(1, interval + 1):
    #                 if j == interval:
    #                     normalList[j - 1] += 1
    #                 if value < (max_value * j / float(interval)):
    #                     normalList[j - 1] += 1
    #                     break
    #
    #     print(dosList)
    #     print(probeList)
    #     print(normalList)
    #     # target = np.array(self.type)
    #     x = list(range(interval))
    #     width = 1 / float(interval)
    #
    #     nameList = []
    #     for i in range(interval):
    #         if i == interval - 1:
    #             nameList.append("[" + str(int(max_value * i / interval)) + ",+)")
    #         else:
    #             nameList.append("[" + str(int(max_value * i / interval)) + "," + str(
    #                 int(max_value * (i + 1) / interval)) + ")")
    #
    #     # nameList = ["[0" + "," + +")", "[11665,23331)",
    #     #             "[23331,34997)", "[34997,46664)",
    #     #             "[46664,58329]"]
    #     plt.bar(x, dosList, width=width, label='DOS', fc='y')
    #     for i in range(len(x)):
    #         x[i] = x[i] + width
    #     plt.bar(x, probeList, width=width, label='Probe', fc='r', tick_label=nameList)
    #     for i in range(len(x)):
    #         x[i] = x[i] + width
    #     plt.bar(x, normalList, width=width, label='normal', fc='b')
    #     plt.legend()
    #     # plt.scatter(X, Y, alpha=0.2, c=target)
    #     plt.xlabel(label[feature_index])
    #     plt.ylabel("sum")
    #     plt.show()

    def visualContinucus(self, feature_index, interval, max_value):

        # dosList = [0 for i in range(interval)]
        # probeList = [0 for i in range(interval)]
        # normalList = [0 for i in range(interval)]
        dosList = []
        probeList = []
        normalList = []
        # length = len(self.data[0])
        # for i in range(length):
        #     value = float(self.data[feature_index][i])
        #     if self.data[28][i] in attackType.Attack.PROBE:
        #         probeList.append(value)
        #     elif self.data[28][i] in attackType.Attack.DOS:
        #         dosList.append(value)
        #     else:
        #         normalList.append(value)
        #
        # print(dosList)
        # print(probeList)
        # print(normalList)
        # target = np.array(self.type)
        X = self.data[feature_index]
        for i in range(len(self.data[0])):
            value = self.data[len(self.data)-1][i]
            if value in attackType.Attack.DOS:
                dosList.append(X[i])
            elif value in attackType.Attack.PROBE:
                probeList.append(X[i])
            else:
                normalList.append(X[i])
        # Y = self.data[len(self.data)-1]


        self.graph_index+=1

        plt.figure(figsize=(10,5),dpi=100)
        Y = [i for i in range(len(normalList))]
        plt.scatter(Y,normalList,color='r',label="normal")

        Y = [i for i in range(len(normalList),len(dosList)+len(normalList))]
        plt.scatter(Y,dosList,color='g',label="DOS")

        Y = [i for i in range(len(dosList)+len(normalList),len(probeList)+len(normalList)+len(dosList))]
        plt.scatter(Y,probeList,color='b',label="Probe")
        # plt.yticks([0,10,20,30,40,50,60,70,80,90,100],(0,0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1))
        plt.yticks([0,3000],(0,58329))
        # plt.yticks([0,137996388,275992776,413989164,551985552,689981940,827978328,965974716‬,1103971104‬,1241967492‬,1379963888],
        # (0,137996388,275992776,413989164,551985552,689981940,827978328,965974716‬,1103971104‬,1241967492‬,1379963888))
        y_major_locator=MultipleLocator(10)
        plt.xlabel(label[feature_index])
        plt.legend()


        plt.savefig(str(feature_index)+".jpg")
        # plt.show()

    def calculateScatter(self, feature_index):
        dosDict = {}
        probeDict = {}
        normalDict = {}

        length = len(self.data[0])
        for i in range(length):
            value = self.data[feature_index][i]
            if self.data[28][i] in attackType.Attack.DOS:
                if value in dosDict.keys():
                    dosDict[value] += 1
                else:
                    dosDict[value] = 1
            elif self.data[28][i] in attackType.Attack.PROBE:
                if value in probeDict.keys():
                    probeDict[value] += 1
                else:
                    probeDict[value] = 1
            else:
                if value in normalDict.keys():
                    normalDict[value] += 1
                else:
                    normalDict[value] = 1

        dosList = []
        probeList = []
        normalList = []
        for value in self.set[feature_index]:
            if value in dosDict.keys():
                dosList.append(dosDict[value])
            else:
                dosList.append(0)
            if value in probeDict.keys():
                probeList.append(probeDict[value])
            else:
                probeList.append(0)
            if value in normalDict.keys():
                normalList.append(normalDict[value])
            else:
                normalList.append(0)

        print(label[feature_index])
        print(self.set[feature_index])
        print("Dos:")
        print(dosList)
        print("Probe:")
        print(probeList)
        print("normal:")
        print(normalList)
        print()


        self.graph_index += 1
        x = [3*i for i in range(len(dosList))]
        width = round(float(3)/(len(dosList)+2),2)
        nameList = [v for v in self.set[feature_index]]

        plt.figure(figsize=(10,5),dpi=100)
        plt.bar(x, dosList, width=width, label='DOS', fc='y',log=True)
        for i in range(len(x)):
            x[i] = x[i] + width
        plt.bar(x, probeList, width=width, label=' Probe', fc='r', tick_label=nameList,log=True)
        for i in range(len(x)):
            x[i] = x[i] + width
        plt.bar(x, normalList, width=width, label='normal', fc='b',log=True)
        plt.legend()

        plt.xlabel(label[feature_index])
        plt.ylabel("sum")
        plt.savefig(str(feature_index)+".jpg")

        # plt.show()


# ax1 = plt.subplot(2,2,1)
# #第一行第二列图形
# ax2 = plt.subplot(2,2,2)
# #第二行
# ax3 = plt.subplot(2,1,2)


if __name__ == "__main__":




    visual = VisualData()
    visual.loadFile("FlowTrain.csv")
    visual.dataToSet()
    # 可视化连续型特征

    # plt.figure(1)

    visual.visualContinucus(0,5,2333)


    # 可视化离散型特征
    # visual.calculateScatter(1)
    # visual.calculateScatter(2)
    # visual.calculateScatter(3)
    # visual.calculateScatter(6)
    # visual.calculateScatter(7)
    # visual.calculateScatter(8)
    # for i in range(11,29):
    #     visual.visualContinucus(i,5,2333)

    # visual.visualContinucus(4,5,2333)
    # visual.visualContinucus(5,5,2333)
    # visual.visualContinucus(12,5,2333)
    # visual.visualContinucus(14,5,2333)
    # visual.visualContinucus(15,5,2333)
    # visual.visualContinucus(16,5,2333)
    # visual.visualContinucus(20,5,2333)
    # visual.visualContinucus(21,5,2333)
    # visual.visualContinucus(25,5,2333)
    # visual.visualContinucus(27,5,2333)
    # visual.visualContinucus(28,5,2333)



