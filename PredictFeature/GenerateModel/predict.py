# coding=utf-8
import sys
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

import csv
import matplotlib.pyplot as plt
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.tree import export_graphviz
from GenerateModel import type
import joblib
import pandas as pd
import pandas.plotting
import mglearn
import seaborn as sns


class PredictModel:
    def __init__(self):
        self.tree = None
        self.feature_name = None
        self.X_train = None
        self.y_train = None
        self.X_test = None
        self.y_test = None

    def loadFile(self, filename):
        with open(filename, "r") as f:
            reader = csv.reader(f)
            datalist = []
            ylist = []
            i = 0
            for row in reader:
                if i == 0:
                    selectRow = row[0:9]
                    self.feature_name = np.array(selectRow)

                if i > 0:
                    selectRow = [type.Protocol.Type[row[0]], type.Service.Type[row[1]], type.Flag.Type[row[2]]]
                    selectRow.extend(row[3:9])
                    datalist.append(selectRow)
                    ylist.append(type.Attack.Type[row[9]])
                i += 1

        X = np.array(datalist)
        y = np.array(ylist)

        self.X_train, self.X_test, self.y_train, self.y_test = \
            train_test_split(X, y, random_state=0)

    def loadTrainAndTestFile(self, trainFileName,
                             testFileName):
        with open(trainFileName, "r") as f:
            reader = csv.reader(f)
            datalist = []
            ylist = []
            i = 0
            for row in reader:
                if i == 0:
                    selectRow = row[0:len(row) - 1]
                    self.feature_name = np.array(selectRow)
                else:
                    selectRow = [row[0], type.Protocol.Type[row[1]], type.Service.Type[row[2]], type.Flag.Type[row[3]]]
                    # selectRow = [type.Protocol.Type[row[0]], type.Service.Type[row[1]], type.Flag.Type[row[2]]]
                    selectRow.extend(row[4:len(row) - 1])
                    datalist.append(selectRow)

                    if row[len(row) - 1] == "normal":
                        ylist.append(0)
                    # elif row[len(row) - 1] in type.Attack.DOS:
                    #     ylist.append(1)
                    # elif row[len(row) - 1] in type.Attack.PROBE:
                    #     ylist.append(2)
                    else:
                        ylist.append(1)

                i += 1
            self.X_train = np.array(datalist)
            self.y_train = np.array(ylist)

        with open(testFileName, "r") as f:
            reader = csv.reader(f)
            datalist = []
            ylist = []
            i = 0
            for row in reader:
                if i == 0:
                    selectRow = row[0:len(row) - 1]
                    self.feature_name = np.array(selectRow)
                else:

                    selectRow = [row[0], type.Protocol.Type[row[1]], type.Service.Type[row[2]], type.Flag.Type[row[3]]]
                    # selectRow = [type.Protocol.Type[row[0]], type.Service.Type[row[1]], type.Flag.Type[row[2]]]
                    selectRow.extend(row[4:len(row) - 1])
                    datalist.append(selectRow)

                    if row[len(row) - 1] == "normal":
                        ylist.append(0)
                    # elif row[len(row) - 1] in type.Attack.DOS:
                    #     ylist.append(1)
                    # elif row[len(row) - 1] in type.Attack.PROBE:
                    #     ylist.append(2)
                    else:
                        ylist.append(1)
                i += 1

            self.X_test = np.array(datalist)
            self.y_test = np.array(ylist)

    def train(self, depth, modelFileName):

        tree = DecisionTreeClassifier(criterion='entropy', splitter="best", max_depth=depth,random_state=30)  # 13
        tree.fit(self.X_train, self.y_train)
        joblib.dump(tree, "../model/" + modelFileName)

        with open("tree.dot", "w", encoding='utf-8') as f:
            f = export_graphviz(tree, feature_names=self.feature_name,
                                class_names=["0", "1"], out_file=f)

        train_accuracy = tree.score(self.X_train, self.y_train)
        test_accuracy = tree.score(self.X_test, self.y_test)
        print("Accuracy on training set: {:.3f}".format(train_accuracy))
        print("Accuracy on test set: {:.3f}".format(test_accuracy))

    def loadModel(self, modelFileName):
        self.tree = joblib.load(modelFileName)

    def predict(self, feature):
        feature[0][1] = type.Protocol.Type[feature[0][1]]
        label = self.tree.predict(feature)
        print(label)
        return label[0]

    def selectDepth(self, max_depth):

        neighbors_settings = range(1, max_depth)
        test_accuracys = []
        training_accuracys = []
        for i in neighbors_settings:
            tree = DecisionTreeClassifier(criterion='entropy', splitter="best", max_depth=i,random_state=30)  # 13
            tree.fit(self.X_train, self.y_train)

            train_accuracy = tree.score(self.X_train, self.y_train)
            test_accuracy = tree.score(self.X_test, self.y_test)

            training_accuracys.append(train_accuracy)
            test_accuracys.append(test_accuracy)
            print("//////////////////////////" + str(i) + "//////////////////////////////")
            print("Accuracy on training set: {:.3f}".format(train_accuracy))
            print("Accuracy on test set: {:.3f}".format(test_accuracy))
            print("")

        plt.plot(neighbors_settings, training_accuracys, label="training accuracy")
        plt.plot(neighbors_settings, test_accuracys, label="test accuracy")

        for i in range(len(neighbors_settings)):
            plt.text(neighbors_settings[i], training_accuracys[i], round(training_accuracys[i], 3))
            plt.text(neighbors_settings[i], test_accuracys[i], round(test_accuracys[i], 3))

        plt.ylabel("Accuracy")
        plt.xlabel("max_depth")
        plt.legend()
        plt.show()
        # plt.savefig("../data/depthAccuracy.jpg")

    # def showGraph(self):
    #     X_train, X_test, y_train, y_test = train_test_split(
    #         self.X, self.y, random_state=0)
    #
    #     iris = sns.load_dataset("iris")
    #     featur_dataframe = pd.DataFrame(X_train, columns=self.feature_name)
    #     g4 = sns.pairplot(featur_dataframe, hue="label")
    #
    #     plt.show()
    #     print()
    #     # feature_dataframe = pd.DataFrame(X_train,columns=self.feature_name)
    #     # grr = pandas.plotting.scatter_matrix(feature_dataframe,
    #     #                                      c=y_train, figsize=(15, 15),
    #     #                                      marker="o", hist_kwds={"bins": 20},
    #     #                                      s=60, alpha=.8, cmap=mglearn.cm3)
    #     # plt.show()


if __name__ == "__main__":
    trainModel = PredictModel()
    # trainModel.loadFile("../data/KDDTest+.csv")
    # trainModel.loadTrainAndTestFile("../data/normalizeTrain.csv",
    #                                 "../data/normalizeTest.csv")


    # trainModel.showGraph()
    # trainModel.selectDepth(10)

    trainModel.loadTrainAndTestFile("../data/RightTrain.csv",
                                    "../data/RightTest.csv")
    trainModel.selectDepth(11)

    trainModel.train(5, "../model/train_model.pkl")
