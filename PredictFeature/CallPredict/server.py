# coding=utf-8
import sys
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]
sys.path.append(rootPath)

import CallPredict.data_pb2 as pb2
import CallPredict.data_pb2_grpc as pb2_grpc
import grpc
from concurrent import futures
import time
import CallPredict.flowFeature as flowFeature
from GenerateModel.predict import PredictModel


class PredictFlow():
    def predict(self, request, context):
        feature = flowFeature.FlowFeature(request)
        data = feature.toNpArray()
        print(data)
        predictModel = PredictModel()
        predictModel.loadModel("../model/train_model.pkl")
        label = predictModel.predict(data)
        return pb2.Response(label=label)


def servers():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    pb2_grpc.add_PredictFlowServicer_to_server(PredictFlow(), server)

    server.add_insecure_port("[::]:50051")
    server.start()

    try:
        while True:
            time.sleep(60 * 60 * 24)
    except KeyboardInterrupt:
        server.stop(0)


if __name__ == "__main__":
    servers()
