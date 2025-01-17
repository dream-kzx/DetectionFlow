# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
import grpc

import CallPredict.data_pb2 as data__pb2


class PredictFlowStub(object):
  # missing associated documentation comment in .proto file
  pass

  def __init__(self, channel):
    """Constructor.

    Args:
      channel: A grpc.Channel.
    """
    self.predict = channel.unary_unary(
        '/CallPredict.PredictFlow/predict',
        request_serializer=data__pb2.Request.SerializeToString,
        response_deserializer=data__pb2.Response.FromString,
        )


class PredictFlowServicer(object):
  # missing associated documentation comment in .proto file
  pass

  def predict(self, request, context):
    # missing associated documentation comment in .proto file
    pass
    context.set_code(grpc.StatusCode.UNIMPLEMENTED)
    context.set_details('Method not implemented!')
    raise NotImplementedError('Method not implemented!')


def add_PredictFlowServicer_to_server(servicer, server):
  rpc_method_handlers = {
      'predict': grpc.unary_unary_rpc_method_handler(
          servicer.predict,
          request_deserializer=data__pb2.Request.FromString,
          response_serializer=data__pb2.Response.SerializeToString,
      ),
  }
  generic_handler = grpc.method_handlers_generic_handler(
      'CallPredict.PredictFlow', rpc_method_handlers)
  server.add_generic_rpc_handlers((generic_handler,))
