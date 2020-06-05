# DetectionFlow
网络异常流量检测系统


编译命令
在ExtractFeature下先执行
sudo ./astilectron-bundler

进入PredictFeature的CallPredict目录下执行
python3 server.py启动grpc流量预测服务

然后进行ExtractFeature下执行
sudo go run *.go
