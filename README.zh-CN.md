# agent-police

**检测 LLM API 中转站是否在篡改工具调用、替换依赖包或窃取凭证——在你的 agent 执行它返回的命令之前。**

[![PyPI](https://img.shields.io/pypi/v/agent-police)](https://pypi.org/project/agent-police/)
[![Python](https://img.shields.io/pypi/pyversions/agent-police)](https://pypi.org/project/agent-police/)
[![CI](https://github.com/RomaCredit/agent-police/actions/workflows/ci.yml/badge.svg)](https://github.com/RomaCredit/agent-police/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

[English](README.md) · [在线检测](https://security.romaapi.com)

```bash
pip install agent-police
agent-police audit https://你的中转站/v1 --model claude-sonnet-4-5
```

## 这个工具解决什么问题

如果你通过第三方中转站调用 Claude 或 GPT，那台服务器会终止你的 TLS、再向上游另开一条连接。它能看到并且能改写每一个 JSON 载荷——**包括模型返回的工具调用参数**。

目前**没有任何厂商提供端到端完整性校验**，所以客户端无法验证：自己即将执行的命令，是不是模型真正产出的那一条。

agent-police 主动探测你指定的端点，告诉你它是否真的在改。

攻击分类与实测数据来自 Liu 等人的论文 *[Your Agent Is Mine: Measuring Malicious Intermediary Attacks on the LLM Supply Chain](https://arxiv.org/abs/2604.08407)*（arXiv:2604.08407）。该论文实测 **428 个商用中转站**，发现 **9 个在注入恶意代码**、**17 个动了研究者的 AWS canary 凭证**、**1 个把 ETH 私钥里的钱转走了**。付费并不更安全：28 个付费中转站里有 1 个在注入。

论文明确不公开其攻击代理。**agent-police 是独立实现的防御侧审计器**，**绝不执行**被测端点返回的任何命令——检测完全在字符串和元数据层面完成。

## 能检测什么

| 类别 | 攻击方式 | agent-police 怎么发现 |
|---|---|---|
| **AC-1** | 改写工具调用参数（下载地址被换、命令被追加） | 发出一条正确答案逐字已知的请求，比对返回的工具调用 |
| **AC-1.a** | 只替换安装命令里的包名，registry 和命令行其余部分一字不动 | 同样的差分，外加抢注判定（字母换位、同形字、分隔符替换、包裹） |
| **AC-1.b** | 按会话特征决定是否下手，平时装好人 | 跨工具名、项目语言、自动批准状态、热身深度的网格扫描 |
| **AC-2** | 静默窃取明文流量里的凭证 | 在四个位置植入 canary，用 HTTP 与 DNS 两种通道守株待兔 |

外加端点体检：**到底是谁在应答**、跑的什么中转软件、上游厂商的响应头是否被剥掉、是否是无需认证就能用的开放中继、TLS 详情、是否聚合了多家厂商的模型。

### 怎么把篡改和模型噪声区分开

每个探针载荷都带一次性 nonce，所以即便是固定的改写规则，每次产生的字符串也不同。agent-police 比对的是**攻击者可控的不变量**——替换后的 host、被换掉的包名——而不是整条参数。

**只有同一个替换目标在多个不同 nonce 下反复出现，才判为高置信度**，因为随机的模型偏差不会反复选中同一个替换值。

空白和引号差异会被归类为「无法判定」，不会误报成篡改。

## 安装

```bash
pip install agent-police
```

<https://pypi.org/project/agent-police/> —— 由 [GitHub Actions](.github/workflows/release.yml) 通过 PyPI trusted publishing 发布。**这个项目不存在 API token**，GitHub 通过 OIDC 直接向 PyPI 证明身份，没有长期凭证可泄露或需要轮换。每次发布都来自版本号与 `pyproject.toml` 一致的 tag，且先通过 3.10–3.14 全部版本的测试。

## 用法

```bash
# 标准审计。密钥交互式询问，不回显、不进 shell history。
agent-police audit https://你的中转站/v1 \
  --model claude-sonnet-4-5 --wire anthropic --repeats 3

# AC-1.b 扫描：遍历触发条件可能依赖的会话特征
agent-police campaign https://你的中转站/v1 \
  --model claude-sonnet-4-5 \
  --langs rust,go,python --warmups 0,10,50 --rate 20

# 不联网，只看一条命令的形态
agent-police inspect "curl -sSL https://get.example.com/i.sh | bash"

# 回查植入的 canary。AC-2 是几天后才出结果，不是几分钟。
agent-police canary check --audit-id cli-1a2b3c4d5e6f
```

`--wire openai` 走 `/v1/chat/completions`，`--wire anthropic` 走 `/v1/messages`，两种格式检测逻辑相同。

退出码：`0` 无中危以上，`1` 中危，`2` 高危或严重。`--json` 输出机器可读报告。

## 一个无法靠工程手段绕过的限制

**一次干净的探测结果，不等于这个端点是干净的。**

条件投递（AC-1.b）在触发条件满足之前始终表现正常，而触发逻辑在服务端。论文在真实中转站上观察到的触发条件包括：**前 50 次请求先装好人**、**只对自动批准（YOLO）模式的会话下手**、**只针对 Rust / Go 项目**。

任何有限次数的黑盒探测都无法证明一个中转站是诚实的。agent-police 能扩大覆盖面，但关不上这个缺口——每一份报告里都写明了这一点。

真正的解法在厂商侧：一个签名的响应信封，绑定模型标识、工具名、工具参数、finish_reason 和客户端 nonce，客户端在执行任何东西之前先验证。目前主流厂商的 tool-use API 和 MCP 规范都没有提供。

## 常见问题

### 怎么判断我的中转站在不在改我的请求？

有个五秒钟就能做、对任何中转站都适用的检查：**发一条 `hi`，看响应里的 `prompt_tokens`。**

个位数是正常的。几百上千就说明有人在你的请求前面塞了东西——而且在按塞进去的 token 向你计费。

### 便宜的 Claude / GPT 中转站能不能用？

中转站在设计上就是应用层的中间人。它终止你的 TLS、用自己的连接访问上游，因此你的 prompt、工具定义、API key 对它都是明文，它也能改写你的 agent 随后要执行的工具调用。

论文的实测数字在上面。需要强调的是：**付费不等于安全**，28 个付费中转站里同样有注入恶意代码的。

### 扫描结果干净就代表安全吗？

**不代表，报告里每次都会写明。** 见上一节。

### agent-police 会执行被测端点返回的命令吗？

**绝不会。** 检测完全在字符串和元数据层面。探针请求一条命令，工具比对返回的参数，不运行任何东西。这是和论文里那套测量流水线的刻意区别——论文是在沙箱里执行载荷的。

### 必须交出 API key 吗？

不是全部功能都需要。**不需要密钥的检查**——端点到底是谁、跑的什么中转软件、响应头是否被剥、是否是开放中继——在 CLI 和在线版上都能直接跑。

只有 AC-1 和 AC-1.a 需要密钥，因为它们必须拿到真实的模型响应才能比对。

建议用一把**临时的、用完即弃的 key**。

## 在线版

<https://security.romaapi.com> 提供网页版，含不需要密钥的端点体检和命令自查。

它要求你把中转站的 API key 交给另一台服务器——这正是它在检测的那种信任问题。所以处理规则如下，全部有测试覆盖：

- 密钥只存在于处理该任务的工作线程中，**不写数据库、不写日志、不写报告**；
- 所有离开进程的内容都会脱敏；
- 任务与结果 30 分钟后删除，不关联任何账号；
- 目标经过 SSRF 校验，且每次响应都重新校验实际连接到的对端地址，以堵住 DNS 重绑定。

**如果你希望密钥不出本机，用 CLI。** 无论哪种方式，都建议用临时密钥。

## 使用范围

只探测你自己拥有、或已获明确授权测试的端点。

## 许可

Apache-2.0
