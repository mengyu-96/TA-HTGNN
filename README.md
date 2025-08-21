#Temporal Heterogeneous Graph Learning for Advanced Persistent Threat Attribution
（面向高级持续性威胁溯源的时序异质图学习）
# APT时序异构图分析工具

## 项目概述

本项目旨在利用时序异构图神经网络（HTGNN）对APT（高级持续性威胁）进行溯源分析。通过从APT报告中提取实体信息，结合Linux安全警报数据，构建时序异构图，并使用HTGNN模型进行分析，以识别APT攻击的模式和关联。

## 功能特点

- **实体关系构建**：从APT报告中提取IP地址、域名、哈希值、文件路径等实体，并构建它们之间的关系
- **时序图生成**：基于时间戳信息，将实体关系组织成时序图，反映APT活动的演变过程
- **数据集整合**：将APTnotes数据集与Linux APT数据集整合，形成更全面的APT活动视图
- **模型适配**：适配HTGNN模型，使其能够处理APT时序异构图数据
- **可视化分析**：提供图形化展示，直观呈现实体关系和分析结果

## 项目结构

```
.
├── APTnotes-tools/                # APT报告实体提取工具
│   ├── extract_entities.py        # 实体提取脚本
│   └── reports_entities.jsonl     # 提取的实体数据
├── HTGNN/                         # HTGNN模型实现
│   ├── model/                     # 模型定义
│   │   └── model.py              # HTGNN模型核心代码
│   └── utils/                     # 工具函数
│       └── data.py               # 数据处理函数
├── Linux-APT-Dataset/             # Linux APT数据集
│   └── Linux-APT-Dataset-2024/    # 2024年数据
│       ├── combine.csv           # 合并的警报数据
│       └── Processed Version.xlsx # 处理后的数据
├── build_entity_relations.py      # 构建实体关系脚本
├── integrate_linux_apt_data.py    # 整合Linux APT数据脚本
├── adapt_htgnn_model.py           # 适配HTGNN模型脚本
├── run_apt_analysis.py            # 运行整个分析流程的脚本
└── README.md                      # 项目说明文档
```

## 安装依赖

本项目需要以下Python库：

```bash
pip install torch dgl networkx matplotlib pandas scikit-learn numpy
```

## 使用方法

### 运行完整分析流程

```bash
python run_apt_analysis.py
```

这将依次执行以下步骤：
1. 构建APT实体关系图
2. 整合Linux APT数据集
3. 训练HTGNN模型

### 跳过特定步骤

```bash
# 跳过构建实体关系图步骤
python run_apt_analysis.py --skip-build

# 跳过整合Linux APT数据步骤
python run_apt_analysis.py --skip-integrate

# 跳过模型训练步骤
python run_apt_analysis.py --skip-model
```

### 单独运行各个步骤

```bash
# 仅构建实体关系图
python build_entity_relations.py

# 仅整合Linux APT数据
python integrate_linux_apt_data.py

# 仅训练模型
python adapt_htgnn_model.py
```

## 输出文件

- **apt_graph.png**：APT实体关系图可视化
- **apt_temporal_graph.bin**：APT时序异构图（DGL格式）
- **integrated_apt_graph.png**：整合后的APT实体关系图可视化
- **integrated_apt_temporal_graph.bin**：整合后的时序异构图（DGL格式）
- **apt_htgnn_model.pt**：训练好的HTGNN模型
- **apt_htgnn_results.json**：模型评估结果
- **node_classification_results.png**：节点分类结果可视化
- **link_prediction_results.png**：链接预测结果可视化

## 实体关系说明

本项目中定义了以下节点类型：

- **report**：APT报告
- **ip**：IP地址
- **domain**：域名
- **hash**：文件哈希值
- **file**：文件路径
- **timestamp**：时间戳
- **alert**：Linux安全警报
- **host**：主机
- **rule**：安全规则

以及以下边类型：

- **report_contains_ip**：报告包含IP
- **report_contains_domain**：报告包含域名
- **report_contains_hash**：报告包含哈希值
- **report_contains_file**：报告包含文件路径
- **report_contains_timestamp**：报告包含时间戳
- **ip_appears_with_domain**：IP与域名共现
- **ip_appears_with_hash**：IP与哈希值共现
- **ip_appears_with_file**：IP与文件共现
- **domain_appears_with_hash**：域名与哈希值共现
- **domain_appears_with_file**：域名与文件共现
- **hash_appears_with_file**：哈希值与文件共现
- **timestamp_of_report**：报告的时间
- **alert_on_host**：警报发生在主机上
- **alert_at_timestamp**：警报发生的时间
- **alert_triggered_by_rule**：警报由规则触发
- **host_has_ip**：主机拥有IP
- **rule_related_to_file**：规则与文件相关

## 模型参数

- **hidden_dim**：64（隐藏层维度）
- **num_heads**：4（注意力头数）
- **num_layers**：2（图神经网络层数）
- **dropout**：0.2（丢弃率）
- **lr**：0.001（学习率）
- **weight_decay**：1e-5（权重衰减）
- **epochs**：100（最大训练轮数）
- **patience**：10（早停耐心值）

## 注意事项

- 确保数据文件路径正确，特别是`APTnotes-tools/reports_entities.jsonl`和`Linux-APT-Dataset/Linux-APT-Dataset-2024/combine.csv`
- 对于大型数据集，可能需要调整模型参数以获得更好的性能
- 时序图生成依赖于数据中的时间戳信息，如果时间信息不足，可能会影响结果

## 扩展与改进

- 添加更多实体类型，如恶意软件家族、攻击战术等
- 优化实体关系构建算法，提高关系的准确性
- 增强时序建模能力，更好地捕捉APT活动的演变
- 添加更多下游任务，如APT组织归因、攻击预测等
- 改进可视化效果，提供交互式分析界面