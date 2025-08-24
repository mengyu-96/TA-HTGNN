import os
import json
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import dgl
import torch
from datetime import datetime
import re

# 文件路径
linux_apt_csv = "Linux-APT-Dataset/Linux-APT-Dataset-2024/combine.csv"
output_graph_file = "integrated_apt_temporal_graph.bin"

# 定义节点类型
NODE_TYPES = {
    'report': 0,    # APT报告
    'ip': 1,        # IP地址
    'domain': 2,    # 域名
    'hash': 3,      # 文件哈希
    'file': 4,      # 文件路径
    'timestamp': 5, # 时间戳
    'process': 6,   # 进程
    'port': 7,      # 网络端口
    'user': 8,      # 用户账户
    'attack_stage': 9,  # 攻击阶段（基于MITRE ATT&CK框架）
    'alert': 10,    # Linux APT数据集中的警报
    'host': 11,     # 主机
    'rule': 12      # 安全规则
}

# 定义边类型
EDGE_TYPES = {
    # 报告与实体的关系
    'report_contains_ip': 0,
    'report_contains_domain': 1,
    'report_contains_hash': 2,
    'report_contains_file': 3,
    'report_contains_timestamp': 4,
    'report_contains_process': 5,
    'report_contains_port': 6,
    'report_contains_user': 7,
    'report_describes_attack_stage': 8,
    
    # 实体共现关系
    'ip_appears_with_domain': 10,
    'ip_appears_with_hash': 11,
    'ip_appears_with_file': 12,
    'domain_appears_with_hash': 13,
    'domain_appears_with_file': 14,
    'hash_appears_with_file': 15,
    
    # 时间关系
    'timestamp_of_report': 20,
    'timestamp_of_attack_stage': 21,
    'timestamp_of_alert': 22,
    
    # 网络通信关系
    'ip_communicates_with_ip': 30,
    'ip_uses_port': 31,
    'domain_resolves_to_ip': 32,
    
    # 进程关系
    'process_creates_process': 40,  # 父进程-子进程
    'process_accesses_file': 41,    # 进程读写文件
    'process_connects_to_ip': 42,   # 进程网络连接
    'process_uses_port': 43,        # 进程使用端口
    
    # 用户关系
    'user_owns_process': 50,        # 用户拥有进程
    'user_accesses_file': 51,       # 用户访问文件
    
    # 攻击阶段关系
    'attack_stage_follows': 60,     # 攻击阶段顺序
    'attack_stage_involves_ip': 61, # 攻击阶段涉及IP
    'attack_stage_involves_domain': 62,
    'attack_stage_involves_file': 63,
    'attack_stage_involves_process': 64,
    
    # Linux APT数据集的边类型
    'alert_on_host': 70,
    'alert_at_timestamp': 71,
    'alert_triggered_by_rule': 72,
    'host_has_ip': 73,
    'rule_related_to_file': 74,
    'host_runs_process': 75,
    'alert_involves_process': 76,
    'alert_involves_file': 77,
    'alert_involves_user': 78,
    'alert_related_to_attack_stage': 79
}

# 加载Linux APT数据集
def load_linux_apt_data():
    try:
        # 使用错误处理机制来处理格式问题
        df = pd.read_csv(linux_apt_csv, on_bad_lines='skip')
        print(f"成功加载Linux APT数据集，共{len(df)}条记录")
        return df
    except Exception as e:
        print(f"加载Linux APT数据集失败: {e}")
        return None

# 从Linux APT数据集中提取IP地址
def extract_ips_from_text(text):
    if not isinstance(text, str):
        return []
    # IPv4正则表达式
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    return re.findall(ip_pattern, text)

# 从Linux APT数据集中提取文件路径
def extract_files_from_text(text):
    if not isinstance(text, str):
        return []
    # 文件路径正则表达式（简化版）
    file_pattern = r'\b/[\w/.-]+\b'
    return re.findall(file_pattern, text)

# 解析时间戳
def parse_timestamp(timestamp_str):
    try:
        # 尝试解析完整的时间戳格式
        return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            # 尝试只解析日期部分
            return datetime.strptime(timestamp_str, "%Y-%m-%d")
        except ValueError:
            try:
                # 尝试解析Linux APT数据集中的时间格式
                return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            except ValueError:
                # 如果无法解析，返回None
                return None

# 构建Linux APT数据的图
def build_linux_apt_graph(df):
    G = nx.DiGraph()
    
    # 处理每一行数据
    for idx, row in df.iterrows():
        # 提取基本信息
        alert_id = f"alert_{idx}"
        host = str(row.get('agent.name', f"host_{idx}"))
        timestamp_str = row.get('@timestamp')
        rule_id = str(row.get('rule.id', f"rule_{idx}"))
        description = str(row.get('rule.description', ''))
        
        # 添加警报节点
        G.add_node(alert_id, type='alert', id=idx)
        
        # 添加主机节点
        if host not in G:
            G.add_node(host, type='host')
        G.add_edge(alert_id, host, type='alert_on_host')
        
        # 添加时间戳节点
        if timestamp_str and isinstance(timestamp_str, str):
            timestamp = parse_timestamp(timestamp_str)
            if timestamp:
                time_str = timestamp.strftime("%Y-%m-%d")
                if time_str not in G:
                    G.add_node(time_str, type='timestamp')
                G.add_edge(alert_id, time_str, type='alert_at_timestamp')
        
        # 添加规则节点
        if rule_id not in G:
            G.add_node(rule_id, type='rule')
        G.add_edge(alert_id, rule_id, type='alert_triggered_by_rule')
        
        # 提取并添加IP地址
        data_str = str(row)
        ips = extract_ips_from_text(data_str)
        for ip in ips:
            if ip not in G:
                G.add_node(ip, type='ip')
            G.add_edge(host, ip, type='host_has_ip')
            G.add_edge(alert_id, ip, type='alert_involves_ip')
        
        # 提取并添加文件路径
        files = extract_files_from_text(data_str)
        for file_path in files:
            if file_path not in G:
                G.add_node(file_path, type='file')
            G.add_edge(rule_id, file_path, type='rule_related_to_file')
            G.add_edge(alert_id, file_path, type='alert_involves_file')
        
        # 尝试提取进程信息
        process_info = row.get('process.name') or row.get('process.executable')
        if process_info and isinstance(process_info, str):
            process_name = process_info.strip()
            if process_name and process_name not in G:
                G.add_node(process_name, type='process')
                G.add_edge(host, process_name, type='host_runs_process')
                G.add_edge(alert_id, process_name, type='alert_involves_process')
                
                # 如果有文件，建立进程与文件的关系
                for file_path in files:
                    G.add_edge(process_name, file_path, type='process_accesses_file')
                
                # 如果有IP，建立进程与IP的关系
                for ip in ips:
                    G.add_edge(process_name, ip, type='process_connects_to_ip')
        
        # 尝试提取端口信息
        port_info = row.get('destination.port') or row.get('source.port')
        if port_info and isinstance(port_info, (int, str)):
            port_str = f"port_{port_info}"
            if port_str not in G:
                G.add_node(port_str, type='port')
                
                # 如果有IP，建立IP与端口的关系
                for ip in ips:
                    G.add_edge(ip, port_str, type='ip_uses_port')
                
                # 如果有进程，建立进程与端口的关系
                if process_info and isinstance(process_info, str):
                    process_name = process_info.strip()
                    if process_name in G:
                        G.add_edge(process_name, port_str, type='process_uses_port')
        
        # 尝试提取用户信息
        user_info = row.get('user.name') or row.get('user.id')
        if user_info and isinstance(user_info, str):
            user_name = user_info.strip()
            if user_name and user_name not in G:
                G.add_node(user_name, type='user')
                G.add_edge(alert_id, user_name, type='alert_involves_user')
                
                # 如果有进程，建立用户与进程的关系
                if process_info and isinstance(process_info, str):
                    process_name = process_info.strip()
                    if process_name in G:
                        G.add_edge(user_name, process_name, type='user_owns_process')
                
                # 如果有文件，建立用户与文件的关系
                for file_path in files:
                    G.add_edge(user_name, file_path, type='user_accesses_file')
        
        # 尝试提取攻击阶段信息（基于规则描述或其他字段）
        attack_stage = None
        if description:
            # 简单的关键词匹配来确定攻击阶段
            if any(keyword in description.lower() for keyword in ['reconnaissance', 'scan', 'discovery']):
                attack_stage = 'Reconnaissance'
            elif any(keyword in description.lower() for keyword in ['exploit', 'vulnerability', 'cve']):
                attack_stage = 'Exploitation'
            elif any(keyword in description.lower() for keyword in ['lateral', 'movement', 'pivot']):
                attack_stage = 'Lateral_Movement'
            elif any(keyword in description.lower() for keyword in ['privilege', 'escalation', 'admin']):
                attack_stage = 'Privilege_Escalation'
            elif any(keyword in description.lower() for keyword in ['data', 'exfiltration', 'transfer']):
                attack_stage = 'Data_Exfiltration'
        
        if attack_stage and attack_stage not in G:
            G.add_node(attack_stage, type='attack_stage')
            G.add_edge(alert_id, attack_stage, type='alert_related_to_attack_stage')
            
            # 如果有时间戳，将攻击阶段与时间关联
            if timestamp and time_str in G:
                G.add_edge(attack_stage, time_str, type='timestamp_of_attack_stage')
            
            # 将攻击阶段与相关实体关联
            for ip in ips:
                G.add_edge(attack_stage, ip, type='attack_stage_involves_ip')
            
            for file_path in files:
                G.add_edge(attack_stage, file_path, type='attack_stage_involves_file')
            
            if process_info and isinstance(process_info, str):
                process_name = process_info.strip()
                if process_name in G:
                    G.add_edge(attack_stage, process_name, type='attack_stage_involves_process')
    
    # 尝试建立攻击阶段之间的顺序关系
    attack_stages = [node for node, data in G.nodes(data=True) if data.get('type') == 'attack_stage']
    attack_stage_order = {
        'Reconnaissance': 1,
        'Exploitation': 2,
        'Privilege_Escalation': 3,
        'Lateral_Movement': 4,
        'Data_Exfiltration': 5
    }
    
    sorted_stages = sorted(attack_stages, key=lambda x: attack_stage_order.get(x, 999))
    for i in range(len(sorted_stages) - 1):
        G.add_edge(sorted_stages[i], sorted_stages[i+1], type='attack_stage_follows')
    
    return G

# 合并两个图
def merge_graphs(apt_graph, linux_graph):
    # 创建一个新图
    merged_graph = nx.DiGraph()
    
    # 添加APT图的所有节点和边
    for node, data in apt_graph.nodes(data=True):
        merged_graph.add_node(node, **data)
    
    for u, v, data in apt_graph.edges(data=True):
        merged_graph.add_edge(u, v, **data)
    
    # 添加Linux APT图的所有节点和边
    for node, data in linux_graph.nodes(data=True):
        if node not in merged_graph:
            merged_graph.add_node(node, **data)
    
    for u, v, data in linux_graph.edges(data=True):
        if not merged_graph.has_edge(u, v):
            merged_graph.add_edge(u, v, **data)
    
    # 尝试建立两个图之间的连接
    # 1. 通过IP地址连接
    apt_ips = [node for node, data in apt_graph.nodes(data=True) if data.get('type') == 'ip']
    linux_ips = [node for node, data in linux_graph.nodes(data=True) if data.get('type') == 'ip']
    
    common_ips = set(apt_ips).intersection(set(linux_ips))
    print(f"两个数据集共有{len(common_ips)}个相同的IP地址")
    
    for apt_ip in apt_ips:
        for linux_ip in linux_ips:
            if apt_ip == linux_ip:
                # 找到相关的报告和警报
                apt_reports = [u for u, v, data in apt_graph.edges(data=True) 
                              if v == apt_ip and data.get('type') == 'report_contains_ip']
                linux_alerts = [u for u, v, data in linux_graph.edges(data=True) 
                               if v == linux_ip and data.get('type') in ['alert_involves_ip', 'host_has_ip']]
                
                # 建立报告和警报之间的连接
                for report in apt_reports:
                    for alert in linux_alerts:
                        merged_graph.add_edge(report, alert, type='report_related_to_alert')
                
                # 找到相关的攻击阶段
                apt_attack_stages = [u for u, v, data in apt_graph.edges(data=True) 
                                   if v == apt_ip and data.get('type') == 'attack_stage_involves_ip']
                linux_attack_stages = [u for u, v, data in linux_graph.edges(data=True) 
                                     if v == linux_ip and data.get('type') == 'attack_stage_involves_ip']
                
                # 建立攻击阶段之间的连接
                for apt_stage in apt_attack_stages:
                    for linux_stage in linux_attack_stages:
                        if apt_stage == linux_stage:  # 如果攻击阶段名称相同
                            merged_graph.add_edge(apt_stage, linux_stage, type='shared_attack_stage')
    
    # 2. 通过文件路径连接
    apt_files = [node for node, data in apt_graph.nodes(data=True) if data.get('type') == 'file']
    linux_files = [node for node, data in linux_graph.nodes(data=True) if data.get('type') == 'file']
    
    common_files = set(apt_files).intersection(set(linux_files))
    print(f"两个数据集共有{len(common_files)}个相同的文件路径")
    
    for apt_file in apt_files:
        for linux_file in linux_files:
            # 简单的字符串匹配，可以改进为更复杂的文件路径匹配
            if apt_file in linux_file or linux_file in apt_file:
                # 找到相关的报告和规则/警报
                apt_reports = [u for u, v, data in apt_graph.edges(data=True) 
                              if v == apt_file and data.get('type') == 'report_contains_file']
                linux_rules = [u for u, v, data in linux_graph.edges(data=True) 
                              if v == linux_file and data.get('type') in ['rule_related_to_file', 'alert_involves_file']]
                
                # 建立报告和规则/警报之间的连接
                for report in apt_reports:
                    for rule in linux_rules:
                        merged_graph.add_edge(report, rule, type='report_related_to_rule')
    
    # 3. 通过时间戳连接
    apt_timestamps = [node for node, data in apt_graph.nodes(data=True) if data.get('type') == 'timestamp']
    linux_timestamps = [node for node, data in linux_graph.nodes(data=True) if data.get('type') == 'timestamp']
    
    common_timestamps = set(apt_timestamps).intersection(set(linux_timestamps))
    print(f"两个数据集共有{len(common_timestamps)}个相同的时间戳")
    
    for apt_ts in apt_timestamps:
        for linux_ts in linux_timestamps:
            # 简单的字符串匹配，可以改进为更复杂的时间匹配
            if apt_ts == linux_ts:
                # 找到相关的报告和警报
                apt_reports = [u for u, v, data in apt_graph.edges(data=True) 
                              if v == apt_ts and data.get('type') == 'report_at_timestamp']
                linux_alerts = [u for u, v, data in linux_graph.edges(data=True) 
                               if v == linux_ts and data.get('type') == 'alert_at_timestamp']
                
                # 建立报告和警报之间的连接
                for report in apt_reports:
                    for alert in linux_alerts:
                        merged_graph.add_edge(report, alert, type='report_related_to_alert_by_time')
                
                # 找到相关的攻击阶段
                apt_attack_stages = [u for u, v, data in apt_graph.edges(data=True) 
                                   if v == apt_ts and data.get('type') == 'timestamp_of_attack_stage']
                linux_attack_stages = [u for u, v, data in linux_graph.edges(data=True) 
                                     if v == linux_ts and data.get('type') == 'timestamp_of_attack_stage']
                
                # 建立攻击阶段之间的连接
                for apt_stage in apt_attack_stages:
                    for linux_stage in linux_attack_stages:
                        merged_graph.add_edge(apt_stage, linux_stage, type='attack_stages_at_same_time')
    
    # 4. 通过进程名称连接
    apt_processes = [node for node, data in apt_graph.nodes(data=True) if data.get('type') == 'process']
    linux_processes = [node for node, data in linux_graph.nodes(data=True) if data.get('type') == 'process']
    
    common_processes = set(apt_processes).intersection(set(linux_processes))
    print(f"两个数据集共有{len(common_processes)}个相同的进程名称")
    
    for apt_process in apt_processes:
        for linux_process in linux_processes:
            # 简单的字符串匹配
            if apt_process == linux_process or apt_process in linux_process or linux_process in apt_process:
                # 找到相关的报告和警报
                apt_reports = [u for u, v, data in apt_graph.edges(data=True) 
                              if v == apt_process and data.get('type') == 'report_contains_process']
                linux_alerts = [u for u, v, data in linux_graph.edges(data=True) 
                               if v == linux_process and data.get('type') == 'alert_involves_process']
                
                # 建立报告和警报之间的连接
                for report in apt_reports:
                    for alert in linux_alerts:
                        merged_graph.add_edge(report, alert, type='report_related_to_alert_by_process')
                
                # 找到相关的攻击阶段
                apt_attack_stages = [u for u, v, data in apt_graph.edges(data=True) 
                                   if v == apt_process and data.get('type') == 'attack_stage_involves_process']
                linux_attack_stages = [u for u, v, data in linux_graph.edges(data=True) 
                                     if v == linux_process and data.get('type') == 'attack_stage_involves_process']
                
                # 建立攻击阶段之间的连接
                for apt_stage in apt_attack_stages:
                    for linux_stage in linux_attack_stages:
                        if apt_stage == linux_stage:  # 如果攻击阶段名称相同
                            merged_graph.add_edge(apt_stage, linux_stage, type='shared_attack_stage')
    
    # 5. 通过攻击阶段连接
    apt_attack_stages = [node for node, data in apt_graph.nodes(data=True) if data.get('type') == 'attack_stage']
    linux_attack_stages = [node for node, data in linux_graph.nodes(data=True) if data.get('type') == 'attack_stage']
    
    common_attack_stages = set(apt_attack_stages).intersection(set(linux_attack_stages))
    print(f"两个数据集共有{len(common_attack_stages)}个相同的攻击阶段")
    
    for apt_stage in apt_attack_stages:
        for linux_stage in linux_attack_stages:
            if apt_stage == linux_stage:  # 如果攻击阶段名称相同
                # 找到相关的报告和警报
                apt_reports = [u for u, v, data in apt_graph.edges(data=True) 
                              if v == apt_stage and data.get('type') == 'report_related_to_attack_stage']
                linux_alerts = [u for u, v, data in linux_graph.edges(data=True) 
                               if v == linux_stage and data.get('type') == 'alert_related_to_attack_stage']
                
                # 建立报告和警报之间的连接
                for report in apt_reports:
                    for alert in linux_alerts:
                        merged_graph.add_edge(report, alert, type='report_related_to_alert_by_attack_stage')
    
    return merged_graph

# 将NetworkX图转换为DGL异构图
def convert_to_dgl_graph(nx_graph):
    # 为每种节点类型创建映射
    node_type_to_ids = {}
    for node, data in nx_graph.nodes(data=True):
        node_type = data.get('type')
        if node_type not in node_type_to_ids:
            node_type_to_ids[node_type] = []
        node_type_to_ids[node_type].append(node)
    
    # 为每种节点类型创建ID映射
    node_type_to_id_map = {}
    for node_type, nodes in node_type_to_ids.items():
        node_type_to_id_map[node_type] = {node: i for i, node in enumerate(nodes)}
    
    # 为每种边类型创建边列表
    edge_type_to_edges = {}
    for src, dst, data in nx_graph.edges(data=True):
        edge_type = data.get('type')
        src_type = nx_graph.nodes[src].get('type')
        dst_type = nx_graph.nodes[dst].get('type')
        
        if edge_type is None or src_type is None or dst_type is None:
            continue
        
        edge_key = (src_type, edge_type, dst_type)
        if edge_key not in edge_type_to_edges:
            edge_type_to_edges[edge_key] = ([], [])
        
        # 获取源节点和目标节点的ID
        src_id = node_type_to_id_map[src_type][src]
        dst_id = node_type_to_id_map[dst_type][dst]
        
        # 添加边
        edge_type_to_edges[edge_key][0].append(src_id)
        edge_type_to_edges[edge_key][1].append(dst_id)
    
    # 创建DGL异构图
    dgl_graph = dgl.heterograph(edge_type_to_edges)
    
    # 添加节点特征（这里简单地使用节点ID作为特征）
    for node_type, id_map in node_type_to_id_map.items():
        num_nodes = len(id_map)
        # 创建一个简单的特征矩阵，每个节点用一个one-hot向量表示
        node_features = torch.eye(num_nodes)
        dgl_graph.nodes[node_type].data['feat'] = node_features
    
    return dgl_graph, node_type_to_id_map

# 将图按时间划分为多个快照
def create_temporal_snapshots(nx_graph, num_snapshots=5):
    # 获取所有带有时间戳的节点
    timestamp_nodes = [node for node, data in nx_graph.nodes(data=True) if data.get('type') == 'timestamp']
    
    if not timestamp_nodes:
        print("警告: 图中没有时间戳节点，无法创建时序快照")
        return []
    
    # 解析时间戳并排序
    timestamps = []
    for ts in timestamp_nodes:
        try:
            timestamps.append(datetime.strptime(ts, "%Y-%m-%d"))
        except ValueError:
            print(f"警告: 无法解析时间戳 {ts}，将被忽略")
    
    sorted_timestamps = sorted(timestamps)
    
    if not sorted_timestamps:
        print("警告: 没有有效的时间戳，无法创建时序快照")
        return []
    
    # 计算时间范围
    min_time = sorted_timestamps[0]
    max_time = sorted_timestamps[-1]
    time_range = (max_time - min_time).days
    
    if time_range <= 0:
        print("警告: 时间范围为零或负值，无法创建时序快照")
        return []
    
    # 计算每个快照的时间间隔
    interval = time_range / num_snapshots
    
    # 创建快照
    snapshots = []
    for i in range(num_snapshots):
        # 计算快照的时间范围
        start_time = min_time + datetime.timedelta(days=int(i * interval))
        end_time = min_time + datetime.timedelta(days=int((i + 1) * interval))
        
        # 筛选在该时间范围内的时间戳节点
        snapshot_timestamps = [ts.strftime("%Y-%m-%d") for ts in sorted_timestamps 
                              if start_time <= ts < end_time]
        
        # 创建子图
        subgraph = nx.DiGraph()
        
        # 添加时间戳节点及其关联的节点
        for ts in snapshot_timestamps:
            subgraph.add_node(ts, type='timestamp')
            
            # 获取与该时间戳相关的节点
            for pred in nx_graph.predecessors(ts):
                pred_type = nx_graph.nodes[pred].get('type')
                
                # 添加节点
                subgraph.add_node(pred, **nx_graph.nodes[pred])
                
                # 添加到时间戳的边
                edge_data = nx_graph.get_edge_data(pred, ts)
                if edge_data:
                    subgraph.add_edge(pred, ts, **edge_data)
                
                # 添加关联的所有实体节点和边
                for succ in nx_graph.successors(pred):
                    if succ != ts:  # 避免重复添加时间戳
                        # 添加实体节点
                        subgraph.add_node(succ, **nx_graph.nodes[succ])
                        # 添加边
                        edge_data = nx_graph.get_edge_data(pred, succ)
                        if edge_data:
                            subgraph.add_edge(pred, succ, **edge_data)
        
        # 添加实体之间的关联边
        for node in subgraph.nodes():
            if node in nx_graph:
                for succ in nx_graph.successors(node):
                    if succ in subgraph and nx_graph.nodes[succ].get('type') != 'timestamp':
                        edge_data = nx_graph.get_edge_data(node, succ)
                        if edge_data:
                            subgraph.add_edge(node, succ, **edge_data)
        
        # 将子图转换为DGL图并添加到快照列表
        if subgraph.number_of_nodes() > 0:
            try:
                dgl_subgraph, _ = convert_to_dgl_graph(subgraph)
                snapshots.append(dgl_subgraph)
                print(f"创建了第{i+1}个时序快照，包含{subgraph.number_of_nodes()}个节点和{subgraph.number_of_edges()}条边")
            except Exception as e:
                print(f"警告: 创建第{i+1}个时序快照时出错: {e}")
    
    return snapshots

# 可视化图
def visualize_graph(graph, title="集成APT实体关系图", output_file="integrated_apt_graph.png"):
    plt.figure(figsize=(18, 15))
    
    # 为不同类型的节点设置不同的颜色
    color_map = {
        'report': 'red',
        'ip': 'blue',
        'domain': 'green',
        'hash': 'purple',
        'file': 'orange',
        'timestamp': 'cyan',
        'alert': 'magenta',
        'host': 'brown',
        'rule': 'black',
        'process': 'lime',
        'port': 'pink',
        'user': 'gold',
        'attack_stage': 'darkred'
    }
    
    # 获取节点颜色
    node_colors = [color_map.get(graph.nodes[node].get('type'), 'gray') for node in graph.nodes()]
    
    # 使用spring布局，增加节点间距
    pos = nx.spring_layout(graph, seed=42, k=0.15)
    
    # 根据节点类型设置不同大小
    node_sizes = []
    for node in graph.nodes():
        node_type = graph.nodes[node].get('type')
        if node_type in ['attack_stage', 'report', 'alert']:
            node_sizes.append(80)  # 重要节点更大
        elif node_type in ['ip', 'domain', 'host']:
            node_sizes.append(60)  # 中等重要节点
        else:
            node_sizes.append(40)  # 其他节点
    
    # 绘制节点
    nx.draw_networkx_nodes(graph, pos, node_color=node_colors, alpha=0.8, node_size=node_sizes)
    
    # 绘制边，降低透明度以减少视觉混乱
    nx.draw_networkx_edges(graph, pos, alpha=0.2, arrows=True, width=0.5)
    
    # 添加标题
    plt.title(title, fontsize=16)
    
    # 添加图例
    for node_type, color in color_map.items():
        plt.plot([], [], 'o', color=color, label=node_type)
    plt.legend(fontsize=12)
    
    # 保存图像
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

# 主函数
def main():
    # 加载Linux APT数据集
    linux_df = load_linux_apt_data()
    if linux_df is None:
        print("无法继续，Linux APT数据集加载失败")
        return
    
    # 构建Linux APT图
    print("构建Linux APT图...")
    linux_graph = build_linux_apt_graph(linux_df)
    print(f"Linux APT图构建完成，包含{linux_graph.number_of_nodes()}个节点和{linux_graph.number_of_edges()}条边")
    
    merged_graph = linux_graph
    
    # 统计各类型节点的数量
    node_type_counts = {
    for _, data in merged_graph.nodes(data=True):
        node_type = data.get('type', 'unknown')
        node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1
    
    print("节点类型统计:")
    for node_type, count in node_type_counts.items():
        print(f"  {node_type}: {count}")
    
    # 统计各类型边的数量
    edge_type_counts = {}
    for _, _, data in merged_graph.edges(data=True):
        edge_type = data.get('type', 'unknown')
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1
    
    print("边类型统计:")
    for edge_type, count in edge_type_counts.items():
        print(f"  {edge_type}: {count}")
    
    # 可视化合并后的图
    print("可视化合并后的图...")
    visualize_graph(merged_graph)
    
    # 创建时序快照
    print("创建时序快照...")
    snapshots = create_temporal_snapshots(merged_graph)
    
    # 保存DGL图
    if snapshots:
        print(f"创建了{len(snapshots)}个时序快照")
        print("保存时序异构图...")
        dgl.save_graphs(output_graph_file, snapshots)
        print(f"时序异构图已保存到{output_graph_file}")
    else:
        print("警告: 没有创建任何时序快照，可能是因为缺少时间信息")

if __name__ == "__main__":
    main()