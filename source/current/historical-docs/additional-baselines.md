# 单份凭证签发与呈示的比较口径

本文、ACL、U-Prove 和 Chan–Yuen 使用相同 Type F 参数、C++17/Release/O3 配置和共享群运算后端。四个方案按相同的属性配置 (n,d) 执行，主测点为 (2,2)。图1在 d=2 时测量 n=2 至 5，图3在 n=5 时测量 d=1 至 5。本文候选数固定 ell=64，其余三方案不使用此参数。每次签发一份凭证，不做批量摊销。

## 复现范围

- ACL：注册、盲签发、属性共同开口与签名验证；首次签发包括用户末尾验签。注册可复用，但主比较按首次签发。
- U-Prove：1.1 Revision 5 方程在公共 PBC 群上的代数复现，不是推荐参数 SDK 或互操作编码。微软官方 P-256/Node 源码与测试另存于 baselines/uprove/upstream，参考数据单列在 results/uprove-reference。
- Chan–Yuen：真实 Paillier MtA、诚实执行签发核心、最终签名核验及单次 AND 呈示。原文未具体实例化的 pi_U 和加密相关范围/密钥证明未被替换成空检查；签发逐次记录 operation_complete=0，只报告核心成本与通信下界。

operation_complete 表示所测操作的实现范围，不是安全认证。Chan–Yuen 在签发和呈示中公开同一 C 的关联限制见该目录 README；不能仅凭耗时假定各方案具有相同安全模型。

## 测量

每组预热3次、测量100次；每次新签发凭证，再生成呈示。密码学随机数来自 CSPRNG。公共属性编码和已有用户私钥在计时前准备；承诺开口和证明掩码在相应操作内生成。固定公共基预计算计入参数准备，额外初始化成本存于 setup.csv。

计时输入是已解析的 PBC 对象，不包含网络、共识和人工资料核验。验证包括实际签名或成员证明、属性关系以及实验包装的本地花费标识查重。本文消费和转让采用独立状态副本，副本准备不计时。每配置单独核对真实编码往返。

完整呈示包含凭证/标签/辅助量与证明；本文还包括完整候选列表。共享服务策略、外部核验资料和交易封装不计入响应负载。官方 JSON 编码另表记录，不能与本地二进制长度直接混用。凭证大小不含持有者私密开口。

原始数据的 bytes 是所选输出对象大小，不能作为签发所有消息之和；总通信见 communication.csv。转让公开提交与原持有者私下交付旧开口分别计数。

## 执行

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/bootstrap.ps1
ctest --test-dir build-native --output-on-failure
.venv/Scripts/python.exe scripts/run_experiments.py
.venv/Scripts/python.exe scripts/audit_results.py
.venv/Scripts/python.exe scripts/plot_results.py
```

结果保存至 results/current，图源与输出保存至 figures/current。程序拒绝覆盖已有原始计时文件；独立复现可选择输出目录并向后续工具传相同目录。
