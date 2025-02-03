# AutoPentest

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux-black)
![Status](https://img.shields.io/badge/status-beta-yellow)

AutoPentest 是一个为高级安全工程师设计的自动化渗透测试框架，基于Python开发，集成了多种高级渗透测试工具和技术，支持全流程的自动化渗透测试。

## 🔥 核心特性

- **全流程自动化**：从前期交互到报告生成的完整渗透测试流程
- **智能决策系统**：基于AI的漏洞分析和利用决策
- **模块化设计**：支持自定义扩展和工具集成
- **专业报告生成**：自动生成符合行业标准的渗透测试报告
- **多维度分析**：包含威胁建模、风险评估和攻击面分析
- **企业级安全**：内置多重安全控制机制

## 🏗️ 系统架构

```
AutoPentest/
├── modules/
│   ├── pre_engagement.py    # 前期交互模块
│   ├── info_gathering.py    # 信息收集模块
│   ├── threat_modeling.py   # 威胁建模模块
│   ├── vuln_scanner.py      # 漏洞扫描模块
│   ├── exploit_manager.py   # 漏洞利用模块
│   ├── post_exploit.py      # 后渗透模块
│   ├── ai_analyzer.py       # AI分析模块
│   └── report_generator.py  # 报告生成模块
├── data/
│   ├── config/             # 配置文件
│   ├── templates/          # 报告模板
│   └── payloads/          # Payload库
├── docs/                   # 详细文档
├── tests/                  # 测试用例
├── requirements.txt        # 依赖清单
└── autopentest.py         # 主程序
```

## 🔧 环境要求

- Kali Linux (推荐 2023.1 或更高版本)
- Python 3.9+
- 4GB+ RAM
- 20GB+ 磁盘空间

## 📦 安装指南

1. **克隆仓库**
```bash
git clone https://github.com/yourusername/autopentest.git
cd autopentest
```

2. **安装依赖**
```bash
# 安装系统依赖
sudo apt update
sudo apt install -y python3-pip python3-venv nmap metasploit-framework

# 创建并激活虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装Python依赖
pip install -r requirements.txt
```

3. **配置环境变量**
```bash
cp .env.example .env
# 编辑 .env 文件，设置必要的API密钥和配置
```

## 🚀 快速开始

1. **基本使用**
```bash
# 运行完整渗透测试
sudo python autopentest.py -u example.com --level 3

# 仅运行特定模块
sudo python autopentest.py -u example.com --module vuln_scan
```

2. **Docker部署**
```bash
# 构建镜像
docker-compose build

# 运行测试
docker-compose run --rm autopentest -u example.com --level 3
```

## 📚 模块说明

### 1. 前期交互模块
- 项目信息管理
- 测试范围定义
- 法律授权文档
- 时间安排管理

### 2. 信息收集模块
- 端口扫描
- 服务识别
- DNS枚举
- WHOIS查询
- 目录扫描

### 3. 威胁建模模块
- 资产评估
- 威胁识别
- 风险评分
- 攻击面分析

### 4. 漏洞扫描模块
- Web应用漏洞扫描
- 服务漏洞扫描
- WAF检测与绕过
- 自定义漏洞检测

### 5. 漏洞利用模块
- Metasploit集成
- 自动化利用
- 漏洞验证
- 利用链构建

### 6. 后渗透模块
- 权限提升
- 横向移动
- 数据收集
- 持久性维持

### 7. AI分析模块
- 智能决策支持
- 漏洞关联分析
- 攻击路径规划
- 风险预测

### 8. 报告生成模块
- HTML/PDF报告
- 执行摘要
- 技术细节
- 修复建议

## 📊 输出目录结构

```
reports/
├── port_scan.json       # 端口扫描结果
├── vuln_scan.json       # 漏洞扫描结果
├── exploit_results.json # 漏洞利用结果
├── post_exploit.json    # 后渗透结果
├── ai_analysis.csv      # AI分析报告
├── ai_analysis.json     # AI分析详细数据
├── report.html         # HTML格式报告
└── report.pdf          # PDF格式报告

loot/                   # 收集的数据
└── credentials/        # 凭证信息

bloodhound/            # BloodHound数据
└── collections/       # 域环境分析数据
```

## 🛡️ 安全说明

1. **使用授权**
   - 仅用于授权的渗透测试项目
   - 必须获得目标系统的书面授权

2. **数据保护**
   - 所有敏感数据进行加密存储
   - 测试完成后及时清理数据

3. **合规要求**
   - 遵守当地法律法规
   - 遵守行业安全标准

## 🔍 故障排除

1. **权限问题**
```bash
# 确保以root权限运行
sudo python autopentest.py [options]
```

2. **依赖问题**
```bash
# 检查并修复依赖
pip install -r requirements.txt --upgrade
```

3. **Metasploit连接问题**
```bash
# 启动MSF服务
sudo systemctl start postgresql
sudo msfdb init
```

## 🤝 贡献指南

1. Fork 项目
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 提交 Pull Request

## 📄 版本历史

- v0.1.0 (2024-01) - 初始版本发布
- v0.2.0 (2024-02) - 添加AI分析模块
- v0.3.0 (2024-03) - 添加WAF绕过功能

## 📝 开源协议

本项目采用 MIT 协议 - 详见 [LICENSE](LICENSE) 文件

## 🌟 致谢

感谢以下开源项目的支持：
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [TinyLlama](https://github.com/jzhang38/TinyLlama)

## 📢 免责声明

本工具仅用于授权的渗透测试和安全研究。使用本工具进行未经授权的测试可能违反法律。作者不对任何未经授权的使用负责。 