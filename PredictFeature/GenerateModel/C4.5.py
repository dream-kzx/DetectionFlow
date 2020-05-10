# # coding=utf-8
#
#
# from numpy import *
# from scipy import *
# from math import log
# import operator
# from sklearn.model_selection import train_test_split
#
# """
# 加载训练数据和测试数据，样本中没有给出
# 因此按数据集中的要求切割出3133个样本作为训练集，剩下1044个样本作为测试集
# 使用sklearn库中的train_test_split来划分，每次产生的训练集都是随机的
# 得到的训练集和测试集是包含了标签的
# """
#
#
# def load_data(train_size):
#     data = open("./data.data").readlines()
#     data_set = []
#
#     for line in data:
#         format_line = line.strip().split(',')
#         label = int(format_line[-1])
#
#         if label <= 8:
#             format_line[-1] = '1'
#         elif label == 9 or label == 10:
#             format_line[-1] = '2'
#         else:
#             format_line[-1] = '3'
#         data_set.append(format_line)
#     data_size = len(data)
#     test_data_size = data_size - train_size
#     train_data, test_data = train_test_split(data_set, test_size=test_data_size / data_size)  # 测试集所占的比例
#     return train_data, test_data
#
#
# """
# 决策树的生成，data_set为训练集，attribute_label为属性名列表
# 决策树用字典结构表示，递归的生成
# """
#
#
# def generate_decision_tree(data_set, attribute_label):
#     label_list = [entry[-1] for entry in data_set]
#     if label_list.count(label_list[0]) == len(label_list):
#         return label_list[0]
#     if len(data_set[0]) == 1:
#         return most_voted_attribute(label_list)
#
#
# def attribute_selection_method(data_set):
#     num_attributes = len(data_set[0]) - 1
#     info_D = calc_info_D(data_set)
#     max_grian_rate = 0.0
#     best_attribute_index = -1
#     best_split_point = None
#     continuous = False
#
#     for i in range(num_attributes):
#         attribute_list = [entry[i] for entry in data_set]
#         info_A_D = 0.0
#         split_info_D = 0.0
#         if attribute_list[0] not in set(['M','F','I']):
#             continuous = True
#
#
#
#
#         temp_set = set(attribute_list)
#         attribute_list = [attr for attr in temp_set]
#         split_points = []
#         for index in range(len(attribute_list) - 1):
#             split_points.append(float(attribute_list[index]) +
#                                 float(attribute_list[index + 1]) / 2)

# import pandas as pd
# from sklearn.preprocessing import OneHotEncoder
# from sklearn.preprocessing import LabelBinarizer
# from sklearn.feature_extraction import DictVectorizer
#
#
# def test():
#     data = pd.DataFrame({'name':['Tom','Andy','David'],'age':[20,21,22],'height':[175,165,180]})
#     arr = LabelBinarizer().fit_transform(data['age'])
#     print(arr)
#
#
# if __name__ == "__main__":
#     test()


# import pandas as pd
# import numpy as np, time
# from sklearn import metrics
# from sklearn.model_selection import train_test_split, GridSearchCV
# import catboost as cb
#
# data = pd.read_csv("flights.csv")
# data = data.sample(frac=0.1, random_state=10)
#
# data = data[["MONTH", "DAY", "DAY_OF_WEEK", "AIRLINE", "FLIGHT_NUMBER", "DESTINATION_AIRPORT",
#              "ORIGIN_AIRPORT", "AIR_TIME", "DEPARTURE_TIME", "DISTANCE", "ARRIVAL_DELAY"]]
# data.dropna(inplace=True)
#
# data["ARRIVAL_DELAY"] = (data["ARRIVAL_DELAY"] > 10) * 1
#
# cols = ["AIRLINE", "FLIGHT_NUMBER", "DESTINATION_AIRPORT", "ORIGIN_AIRPORT"]
# for item in cols:
#     data[item] = data[item].astype("category").cat.codes + 1
#
# train, test, y_train, y_test = train_test_split(data.drop(["ARRIVAL_DELAY"], axis=1), data["ARRIVAL_DELAY"],
#                                                 random_state=10, test_size=0.25)
#
#
#
#
# cat_features_index = [0,1,2,3,4,5,6]
#
# def auc(m, train, test):
#     return (metrics.roc_auc_score(y_train,m.predict_proba(train)[:,1]),
#             metrics.roc_auc_score(y_test,m.predict_proba(test)[:,1]))
#
# params = {'depth': [4, 7, 10],
#           'learning_rate' : [0.03, 0.1, 0.15],
#           'l2_leaf_reg': [1,4,9],
#           'iterations': [300]}
# cb = cb.CatBoostClassifier()
# cb_model = GridSearchCV(cb, params, scoring="roc_auc", cv = 3)
# cb_model.fit(train, y_train)
#
# #With Categorical features
# clf = cb.CatBoostClassifier(eval_metric="AUC", depth=10, iterations= 500, l2_leaf_reg= 9, learning_rate= 0.15)
# clf.fit(train,y_train)
# auc(clf, train, test)
#
# #With Categorical features
# clf = cb.CatBoostClassifier(eval_metric="AUC",one_hot_max_size=31, \
#                             depth=10, iterations= 500, l2_leaf_reg= 9, learning_rate= 0.15)
# clf.fit(train,y_train, cat_features= cat_features_index)
# auc(clf, train, test)













# import numpy as np
# import catboost as cb
#
# train_data = np.random.randint(0, 100, size=(100, 10))
# train_label = np.random.randint(0, 2, size=(100))
# test_data = np.random.randint(0,100, size=(50,10))
#
# print(train_data)
# print(train_label)
#
# model = cb.CatBoostClassifier(iterations=2, depth=2, learning_rate=0.5, loss_function='Logloss',
#                               logging_level='Verbose')
# model.fit(train_data, train_label, cat_features=[0,2,5])
# preds_class = model.predict(test_data)
# preds_probs = model.predict_proba(test_data)
# print('class = ',preds_class)
# print('proba = ',preds_probs)
