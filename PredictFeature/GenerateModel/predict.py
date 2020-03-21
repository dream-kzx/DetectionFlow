# coding=utf-8

import csv

import matplotlib.pyplot as plt
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from GenerateModel import type
import joblib


class PredictModel:
    def __init__(self):
        self.tree = None
        self.X = None
        self.y = None

    def loadFile(self, filename):
        with open(filename, "r") as f:
            reader = csv.reader(f)
            datalist = []
            ylist = []
            i = 0
            for row in reader:
                if i > 0:
                    row[1] = type.Protocol.Type[row[1]]
                    row[2] = type.Service.Type[row[2]]
                    row[3] = type.Flag.Type[row[3]]
                    row[41] = type.Attack.Type[row[41]]
                    datalist.append(row[:41])
                    ylist.append(row[41:42])
                i += 1

        self.X = np.array(datalist)
        self.y = np.array(ylist)

    def train(self, depth, modelFileName):
        X_train, X_test, y_train, y_test = train_test_split(
            self.X, self.y, random_state=0)
        tree = DecisionTreeClassifier(random_state=10, max_depth=depth)
        tree.fit(X_train, y_train)
        joblib.dump(tree, "../model/" + modelFileName)

        train_accuracy = tree.score(X_train, y_train)
        test_accuracy = tree.score(X_test, y_test)
        print("Accuracy on training set: {:.3f}".format(train_accuracy))
        print("Accuracy on test set: {:.3f}".format(test_accuracy))

    def loadModel(self, modelFileName):
        self.tree = joblib.load(modelFileName)

    def predict(self, feature):
        feature[0][1] = type.Protocol.Type[feature[0][1]]
        # feature[2] = type.Service.Type[feature[2]]
        # feature[3] = type.Flag.Type[feature[3]]
        # feature[41] = type.Attack.Type[feature[41]]
        label = self.tree.predict(feature)
        return label[0]

    def selectDepth(self, max_depth):
        X_train, X_test, y_train, y_test = train_test_split(
            self.X, self.y, random_state=0)

        neighbors_settings = range(1, max_depth)
        test_accuracys = []
        training_accuracys = []
        for i in neighbors_settings:
            tree = DecisionTreeClassifier(random_state=10, max_depth=i)  # 13
            tree.fit(X_train, y_train)

            train_accuracy = tree.score(X_train, y_train)
            test_accuracy = tree.score(X_test, y_test)

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


if __name__ == "__main__":
    trainModel = PredictModel()
    trainModel.loadFile("../data/KDDTest+.csv")
    # trainModel.selectDepth(20)
    trainModel.train(13, "../model/train_model.pkl")
