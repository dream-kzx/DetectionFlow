# coding=utf-8

import csv

attackMap = set()
with open("KDDTrain+.csv", "r") as f:
    reader = csv.reader(f)
    i = 0
    for row in reader:
        if i != 0:
            attackMap.add(row[41])
        i += 1

with open("KDDTest+.csv", "r") as f:
    reader = csv.reader(f)
    i = 0
    for row in reader:
        if i != 0:
            attackMap.add(row[41])
        i += 1

print(len(attackMap))
i = 1
for x in attackMap:
    print('"'+x+'":'+str(i)+",")
    if x!="normal":
        i+=1
