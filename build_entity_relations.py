import os
import json
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import dgl
import torch
import re

# 文件路径
reports_entities_file = "APTnotes-tools/reports_entities.jsonl"
output_graph_file = "apt_temporal_graph.bin"

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
    'attack_stage': 9  # 攻击阶段（基于MITRE ATT&CK框架）
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
    'attack_stage_involves_process': 64
}

# 加载实体数据
def load_entities():
    entities_data = []
    with open(reports_entities_file, 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            # 确保所有实体类型都存在
            if 'entities' not in data:
                data['entities'] = {}
            
            # 确保基本实体类型存在
            for entity_type in ['ips', 'domains', 'hashes', 'files', 'timestamps']:
                if entity_type not in data['entities']:
                    data['entities'][entity_type] = []
            
            # 添加新的实体类型（如果不存在）
            if 'processes' not in data['entities']:
                data['entities']['processes'] = []
            if 'ports' not in data['entities']:
                data['entities']['ports'] = []
            if 'users' not in data['entities']:
                data['entities']['users'] = []
            if 'attack_stages' not in data['entities']:
                data['entities']['attack_stages'] = []
            
            entities_data.append(data)
    return entities_data

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
            # 如果无法解析，返回None
            return None

# 提取报告中的时间信息
def extract_report_time(report_data):
    timestamps = report_data['entities']['timestamps']
    if not timestamps:
        return None
    
    # 解析所有时间戳
    parsed_timestamps = [parse_timestamp(ts) for ts in timestamps]
    # 过滤掉无法解析的时间戳
    valid_timestamps = [ts for ts in parsed_timestamps if ts is not None]
    
    if not valid_timestamps:
        return None
    
    # 返回最早的时间戳作为报告时间
    return min(valid_timestamps)

# 构建异构图
def build_heterogeneous_graph(entities_data):
    # 创建一个有向图
    G = nx.DiGraph()
    
    # 添加报告节点
    for i, report in enumerate(entities_data):
        report_name = report['report_name']
        G.add_node(report_name, type='report', id=i)
        
        # 提取报告时间
        report_time = extract_report_time(report)
        if report_time:
            time_str = report_time.strftime("%Y-%m-%d")
            # 添加时间戳节点（如果不存在）
            if time_str not in G:
                G.add_node(time_str, type='timestamp')
            # 添加报告与时间戳的边
            G.add_edge(report_name, time_str, type='timestamp_of_report')
        
        # 添加IP节点和边
        for ip in report['entities']['ips']:
            if ip not in G:
                G.add_node(ip, type='ip')
            G.add_edge(report_name, ip, type='report_contains_ip')
        
        # 添加域名节点和边
        for domain in report['entities']['domains']:
            if domain not in G:
                G.add_node(domain, type='domain')
            G.add_edge(report_name, domain, type='report_contains_domain')
        
        # 添加哈希节点和边
        for hash_value in report['entities']['hashes']:
            if hash_value not in G:
                G.add_node(hash_value, type='hash')
            G.add_edge(report_name, hash_value, type='report_contains_hash')
        
        # 添加文件节点和边
        for file_path in report['entities']['files']:
            if file_path not in G:
                G.add_node(file_path, type='file')
            G.add_edge(report_name, file_path, type='report_contains_file')
        
        # 添加进程节点和边
        for process in report['entities']['processes']:
            if process not in G:
                G.add_node(process, type='process')
            G.add_edge(report_name, process, type='report_contains_process')
        
        # 添加端口节点和边
        for port in report['entities']['ports']:
            if port not in G:
                G.add_node(port, type='port')
            G.add_edge(report_name, port, type='report_contains_port')
        
        # 添加用户节点和边
        for user in report['entities']['users']:
            if user not in G:
                G.add_node(user, type='user')
            G.add_edge(report_name, user, type='report_contains_user')
        
        # 添加攻击阶段节点和边
        for attack_stage in report['entities']['attack_stages']:
            if attack_stage not in G:
                G.add_node(attack_stage, type='attack_stage')
            G.add_edge(report_name, attack_stage, type='report_describes_attack_stage')
            
            # 如果有时间戳，将攻击阶段与时间关联
            if report_time:
                G.add_edge(attack_stage, time_str, type='timestamp_of_attack_stage')
    
    # 添加实体之间的关联边
    for report in entities_data:
        # 获取报告中的所有实体
        ips = report['entities']['ips']
        domains = report['entities']['domains']
        hashes = report['entities']['hashes']
        files = report['entities']['files']
        processes = report['entities']['processes']
        ports = report['entities']['ports']
        users = report['entities']['users']
        attack_stages = report['entities']['attack_stages']
        
        # 添加实体共现关系
        # IP与其他实体的共现
        for ip in ips:
            for domain in domains:
                G.add_edge(ip, domain, type='ip_appears_with_domain')
            for hash_value in hashes:
                G.add_edge(ip, hash_value, type='ip_appears_with_hash')
            for file_path in files:
                G.add_edge(ip, file_path, type='ip_appears_with_file')
            for port in ports:
                G.add_edge(ip, port, type='ip_uses_port')
            # IP之间的通信关系（如果有多个IP）
            for other_ip in ips:
                if ip != other_ip:
                    G.add_edge(ip, other_ip, type='ip_communicates_with_ip')
        
        # 域名与其他实体的共现
        for domain in domains:
            for hash_value in hashes:
                G.add_edge(domain, hash_value, type='domain_appears_with_hash')
            for file_path in files:
                G.add_edge(domain, file_path, type='domain_appears_with_file')
            # 域名解析到IP
            for ip in ips:
                G.add_edge(domain, ip, type='domain_resolves_to_ip')
        
        # 哈希与文件的共现
        for hash_value in hashes:
            for file_path in files:
                G.add_edge(hash_value, file_path, type='hash_appears_with_file')
        
        # 进程关系
        for i, process in enumerate(processes):
            # 进程与文件的关系
            for file_path in files:
                G.add_edge(process, file_path, type='process_accesses_file')
            # 进程与IP的关系
            for ip in ips:
                G.add_edge(process, ip, type='process_connects_to_ip')
            # 进程与端口的关系
            for port in ports:
                G.add_edge(process, port, type='process_uses_port')
            # 进程之间的父子关系（如果有多个进程，假设按顺序有父子关系）
            if i < len(processes) - 1:
                G.add_edge(process, processes[i+1], type='process_creates_process')
        
        # 用户关系
        for user in users:
            # 用户与进程的关系
            for process in processes:
                G.add_edge(user, process, type='user_owns_process')
            # 用户与文件的关系
            for file_path in files:
                G.add_edge(user, file_path, type='user_accesses_file')
        
        # 攻击阶段关系
        for i, attack_stage in enumerate(attack_stages):
            # 攻击阶段之间的顺序关系
            if i < len(attack_stages) - 1:
                G.add_edge(attack_stage, attack_stages[i+1], type='attack_stage_follows')
            # 攻击阶段与实体的关系
            for ip in ips:
                G.add_edge(attack_stage, ip, type='attack_stage_involves_ip')
            for domain in domains:
                G.add_edge(attack_stage, domain, type='attack_stage_involves_domain')
            for file_path in files:
                G.add_edge(attack_stage, file_path, type='attack_stage_involves_file')
            for process in processes:
                G.add_edge(attack_stage, process, type='attack_stage_involves_process')
    
    return G

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
    
    # 解析时间戳并排序
    timestamps = [datetime.strptime(ts, "%Y-%m-%d") for ts in timestamp_nodes]
    sorted_timestamps = sorted(timestamps)
    
    if not sorted_timestamps:
        return []
    
    # 计算时间范围
    min_time = sorted_timestamps[0]
    max_time = sorted_timestamps[-1]
    time_range = (max_time - min_time).days
    
    # 计算每个快照的时间间隔
    interval = time_range / num_snapshots
    
    # 创建快照
    snapshots = []
    for i in range(num_snapshots):
        # 计算快照的时间范围
        start_time = min_time + datetime.timedelta(days=i * interval)
        end_time = min_time + datetime.timedelta(days=(i + 1) * interval)
        
        # 筛选在该时间范围内的时间戳节点
        snapshot_timestamps = [ts.strftime("%Y-%m-%d") for ts in sorted_timestamps 
                              if start_time <= ts < end_time]
        
        # 创建子图
        subgraph = nx.DiGraph()
        
        # 添加时间戳节点及其关联的报告节点
        for ts in snapshot_timestamps:
            subgraph.add_node(ts, type='timestamp')
            # 获取与该时间戳相关的报告
            for pred in nx_graph.predecessors(ts):
                if nx_graph.nodes[pred].get('type') == 'report':
                    # 添加报告节点
                    subgraph.add_node(pred, **nx_graph.nodes[pred])
                    # 添加报告到时间戳的边
                    subgraph.add_edge(pred, ts, type='timestamp_of_report')
                    
                    # 添加报告关联的所有实体节点和边
                    for succ in nx_graph.successors(pred):
                        node_type = nx_graph.nodes[succ].get('type')
                        if node_type in ['ip', 'domain', 'hash', 'file']:
                            # 添加实体节点
                            subgraph.add_node(succ, **nx_graph.nodes[succ])
                            # 添加报告到实体的边
                            edge_type = f'report_contains_{node_type}'
                            subgraph.add_edge(pred, succ, type=edge_type)
        
        # 添加实体之间的关联边
        for node in subgraph.nodes():
            if node in nx_graph:
                for succ in nx_graph.successors(node):
                    if succ in subgraph and nx_graph.nodes[succ].get('type') != 'timestamp':
                        edge_data = nx_graph.get_edge_data(node, succ)
                        if edge_data and 'type' in edge_data:
                            subgraph.add_edge(node, succ, **edge_data)
        
        # 将子图转换为DGL图并添加到快照列表
        if subgraph.number_of_nodes() > 0:
            dgl_subgraph, _ = convert_to_dgl_graph(subgraph)
            snapshots.append(dgl_subgraph)
    
    return snapshots

# 可视化图
def visualize_graph(graph, title="APT实体关系图", output_file="apt_graph.png"):
    plt.figure(figsize=(15, 12))
    
    # 为不同类型的节点设置不同的颜色
    color_map = {
        'report': 'red',
        'ip': 'blue',
        'domain': 'green',
        'hash': 'purple',
        'file': 'orange',
        'timestamp': 'cyan',
        'process': 'magenta',
        'port': 'brown',
        'user': 'pink',
        'attack_stage': 'black'
    }
    
    # 获取节点颜色
    node_colors = [color_map.get(graph.nodes[node].get('type'), 'gray') for node in graph.nodes()]
    
    # 使用spring布局
    pos = nx.spring_layout(graph, seed=42)
    
    # 绘制节点
    nx.draw_networkx_nodes(graph, pos, node_color=node_colors, alpha=0.8, node_size=80)
    
    # 绘制边
    nx.draw_networkx_edges(graph, pos, alpha=0.4, arrows=True, width=0.5)
    
    # 添加标题
    plt.title(title)
    
    # 添加图例
    for node_type, color in color_map.items():
        plt.plot([], [], 'o', color=color, label=node_type)
    plt.legend()
    
    # 保存图像
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

# 主函数
def main():
    print("加载实体数据... - build_entity_relations.py:455")
    entities_data = load_entities()
    
    print(f"共加载了 {len(entities_data)} 个报告的实体数据 - build_entity_relations.py:458")
    
    print("构建异构图... - build_entity_relations.py:460")
    nx_graph = build_heterogeneous_graph(entities_data)
    
    print(f"图构建完成，包含 {nx_graph.number_of_nodes()} 个节点和 {nx_graph.number_of_edges()} 条边 - build_entity_relations.py:463")
    
    # 统计各类型节点的数量
    node_type_counts = {}
    for _, data in nx_graph.nodes(data=True):
        node_type = data.get('type', 'unknown')
        node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1
    
    print("节点类型统计: - build_entity_relations.py:471")
    for node_type, count in node_type_counts.items():
        print(f"{node_type}: {count} - build_entity_relations.py:473")
    
    # 统计各类型边的数量
    edge_type_counts = {}
    for _, _, data in nx_graph.edges(data=True):
        edge_type = data.get('type', 'unknown')
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1
    
    print("边类型统计: - build_entity_relations.py:481")
    for edge_type, count in edge_type_counts.items():
        print(f"{edge_type}: {count} - build_entity_relations.py:483")
    
    print("可视化图... - build_entity_relations.py:485")
    visualize_graph(nx_graph)
    
    print("转换为DGL异构图... - build_entity_relations.py:488")
    dgl_graph, node_maps = convert_to_dgl_graph(nx_graph)
    
    print("创建时序快照... - build_entity_relations.py:491")
    snapshots = create_temporal_snapshots(nx_graph)
    
    print(f"创建了 {len(snapshots)} 个时序快照 - build_entity_relations.py:494")
    
    # 保存DGL图
    if snapshots:
        print("保存时序异构图... - build_entity_relations.py:498")
        dgl.save_graphs(output_graph_file, snapshots)
        print(f"时序异构图已保存到 {output_graph_file} - build_entity_relations.py:500")
    else:
        print("警告: 没有创建任何时序快照，可能是因为缺少时间信息 - build_entity_relations.py:502")

if __name__ == "__main__":
    main()