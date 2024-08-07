# 网站篡改检测（WebsiteTamperingDetector）

## 环境要求

1. Python3
2. pip3 install -r requirements.txt
3. ChromeDriver & Chrome

## 使用方法

1. 将需要检测的网站域名写入input.txt文件中
2. python3 main.py
3. 检测完成后结果将输出到output.xlsx文件中

## 准确率

使用input.txt中的1万个域名进行测试，经人工验证，准确率约为96%
（2024年8月测试，仅验证IP在中国大陆境内的网站，IP在中国大陆境外的网站仅供参考）

## 开源协议

GPL-3.0
