@echo off
kind create cluster --config ./kind-config.yaml

kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

timeout /t 15 /nobreak >nul


kubectl patch -n kube-system deployment metrics-server --type=json ^
 -p "[{\"op\":\"add\",\"path\":\"/spec/template/spec/containers/0/args/-\",\"value\":\"--kubelet-insecure-tls\"}]"

kubectl apply -f k8/

