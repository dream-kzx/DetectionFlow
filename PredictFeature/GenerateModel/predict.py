# coding=utf-8

import csv

import matplotlib.pyplot as plt
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
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
                selectRow = []
                if i == 0:
                    # self.feature_name = np.array(row[:9] + row[41:42])
                    selectRow.append(row[1])
                    selectRow.append(row[2])
                    selectRow.append(row[3])
                    selectRow.append(row[4])
                    selectRow.append(row[28])
                    selectRow.append(row[32])
                    selectRow.append(row[33])
                    selectRow.append(row[34])
                    selectRow.append(row[38])
                    self.feature_name = np.array(selectRow)

                if i > 0:
                    selectRow.append(type.Protocol.Type[row[1]])
                    selectRow.append(type.Service.Type[row[2]])
                    selectRow.append(type.Flag.Type[row[3]])
                    selectRow.append(row[4])
                    selectRow.append(row[28])
                    selectRow.append(row[32])
                    selectRow.append(row[33])
                    selectRow.append(row[34])
                    selectRow.append(row[38])
                    datalist.append(selectRow)
                    # datalist.append(row[:41])
                    # datalist.append(row[:9] + row[41:42])
                    # ylist.append(row[41:42])
                    ylist.append(type.Attack.Type[row[41]])
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
                selectRow = []
                if i == 0:
                    selectRow.append(row[1])
                    selectRow.append(row[2])
                    selectRow.append(row[3])
                    selectRow.append(row[4])
                    selectRow.append(row[28])
                    selectRow.append(row[32])
                    selectRow.append(row[33])
                    selectRow.append(row[34])
                    selectRow.append(row[38])
                    self.feature_name = np.array(selectRow)

                elif i > 0 and row[41] not in type.Attack.R2L \
                        and row[41] not in type.Attack.U2R:
                    selectRow.append(type.Protocol.Type[row[1]])
                    selectRow.append(type.Service.Type[row[2]])
                    selectRow.append(type.Flag.Type[row[3]])
                    selectRow.append(row[4])
                    selectRow.append(row[28])
                    selectRow.append(row[32])
                    selectRow.append(row[33])
                    selectRow.append(row[34])
                    selectRow.append(row[38])
                    datalist.append(selectRow)
                    if row[41] == "normal":
                        ylist.append(0)
                    elif row[41] in type.Attack.DOS:
                        ylist.append(1)
                    elif row[41] in type.Attack.PROBE:
                        ylist.append(2)
                    else:
                        print("error (predict.py 110)")

                    # ylist.append(type.Attack.Type[row[41]])
                i += 1
            self.X_train = np.array(datalist)
            self.y_train = np.array(ylist)

        with open(testFileName, "r") as f:
            reader = csv.reader(f)
            datalist = []
            ylist = []
            i = 0
            for row in reader:
                selectRow = []
                if i > 0 and row[41] not in type.Attack.R2L \
                        and row[41] not in type.Attack.U2R:
                    selectRow.append(type.Protocol.Type[row[1]])
                    selectRow.append(type.Service.Type[row[2]])
                    selectRow.append(type.Flag.Type[row[3]])
                    selectRow.append(row[4])
                    selectRow.append(row[28])
                    selectRow.append(row[32])
                    selectRow.append(row[33])
                    selectRow.append(row[34])
                    selectRow.append(row[38])
                    datalist.append(selectRow)
                    # ylist.append(type.Attack.Type[row[41]])
                    if row[41] == "normal":
                        ylist.append(0)
                    elif row[41] in type.Attack.DOS:
                        ylist.append(1)
                    elif row[41] in type.Attack.PROBE:
                        ylist.append(2)
                    else:
                        print("error (predict.py 145)")

                i += 1
            self.X_test = np.array(datalist)
            self.y_test = np.array(ylist)

    def train(self, depth, modelFileName):

        tree = DecisionTreeClassifier(random_state=10, max_depth=depth)
        tree.fit(self.X_train, self.y_train)
        joblib.dump(tree, "../model/" + modelFileName)

        train_accuracy = tree.score(self.X_train, self.y_train)
        test_accuracy = tree.score(self.X_test, self.y_test)
        print("Accuracy on training set: {:.3f}".format(train_accuracy))
        print("Accuracy on test set: {:.3f}".format(test_accuracy))

    def loadModel(self, modelFileName):
        self.tree = joblib.load(modelFileName)

    def predict(self, feature):
        feature[0][0] = type.Protocol.Type[feature[0][0]]
        label = self.tree.predict(feature)
        return label[0]

    def selectDepth(self, max_depth):

        neighbors_settings = range(1, max_depth)
        test_accuracys = []
        training_accuracys = []
        for i in neighbors_settings:
            tree = DecisionTreeClassifier(random_state=10, max_depth=i)  # 13
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
        plt.ylabel("Accuracy")
        plt.xlabel("n_neighbors")
        plt.legend()
        plt.show()

    def showGraph(self):
        X_train, X_test, y_train, y_test = train_test_split(
            self.X, self.y, random_state=0)

        iris = sns.load_dataset("iris")
        featur_dataframe = pd.DataFrame(X_train, columns=self.feature_name)
        g4 = sns.pairplot(featur_dataframe, hue="label")

        plt.show()
        print()
        # feature_dataframe = pd.DataFrame(X_train,columns=self.feature_name)
        # grr = pandas.plotting.scatter_matrix(feature_dataframe,
        #                                      c=y_train, figsize=(15, 15),
        #                                      marker="o", hist_kwds={"bins": 20},
        #                                      s=60, alpha=.8, cmap=mglearn.cm3)
        # plt.show()


if __name__ == "__main__":
    trainModel = PredictModel()
    # trainModel.loadFile("../data/KDDTest+.csv")
    trainModel.loadTrainAndTestFile("../data/KDDTrain+.csv",
                                    "../data/KDDTest+.csv")
    # trainModel.showGraph()
    # trainModel.selectDepth(20)
    trainModel.train(4, "../model/train_model.pkl")
