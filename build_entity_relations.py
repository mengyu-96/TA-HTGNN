import os
import json
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
<<<<<<< Updated upstream
from datetime import datetime, timedelta
import dgl
import torch
=======
from datetime import datetime
>>>>>>> Stashed changes
import re
# 暂时移除DGL和torch依赖
# import dgl
# import torch

# 文件路径
output_graph_file = "apt_temporal_graph.bin"
linux_apt_csv = "Linux-APT-Dataset/Linux-APT-Dataset-2024/combine.csv"

# 定义节点类型
NODE_TYPES = {
    'report': 0,  # APT报告
    'ip': 1,  # IP地址
    'domain': 2,  # 域名
    'hash': 3,  # 文件哈希
    'file': 4,  # 文件路径
    'timestamp': 5,  # 时间戳
    'process': 6,  # 进程
    'port': 7,  # 网络端口
    'user': 8,  # 用户账户
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
    'process_accesses_file': 41,  # 进程读写文件
    'process_connects_to_ip': 42,  # 进程网络连接
    'process_uses_port': 43,  # 进程使用端口

    # 用户关系
    'user_owns_process': 50,  # 用户拥有进程
    'user_accesses_file': 51,  # 用户访问文件

    # 攻击阶段关系
    'attack_stage_follows': 60,  # 攻击阶段顺序
    'attack_stage_involves_ip': 61,  # 攻击阶段涉及IP
    'attack_stage_involves_domain': 62,
    'attack_stage_involves_file': 63,
    'attack_stage_involves_process': 64
}


# 加载实体数据
def load_entities():
    try:
        # 使用错误处理机制来处理格式问题，设置low_memory=False消除数据类型警告
        df = pd.read_csv(linux_apt_csv, on_bad_lines='skip', low_memory=False)
        print(f"成功加载Linux APT数据集，共{len(df)}条记录")
        
        # 打印列名，帮助调试
        print("CSV文件列名:")
        print(df.columns.tolist()[:20])  # 打印前20个列名，提供更多信息
        
        # 尝试从数据中提取实体信息
        entities_data = []
        
        # 扩展字段搜索范围
        ip_fields = ['_source.data.srcip', '_source.agent.ip', '_source.data.win.eventdata.ipAddress', 
                    '_source.data.dstip', '_source.data.win.eventdata.destinationIp']
        ip_fields = [field for field in ip_fields if field in df.columns]
        
        user_fields = ['_source.data.srcuser', '_source.data.dstuser', '_source.data.user', 
                      '_source.data.win.eventdata.targetUserName', '_source.data.win.eventdata.subjectUserName']
        user_fields = [field for field in user_fields if field in df.columns]
        
        file_fields = ['_source.data.file', '_source.syscheck.path', '_source.data.win.eventdata.targetFilename', 
                      '_source.data.win.eventdata.image']
        file_fields = [field for field in file_fields if field in df.columns]
        
        process_fields = ['_source.data.process', '_source.data.command', '_source.data.win.eventdata.processName', 
                         '_source.data.win.eventdata.parentProcessName']
        process_fields = [field for field in process_fields if field in df.columns]
        
        timestamp_fields = ['_source.@timestamp', '_source.timestamp']
        timestamp_fields = [field for field in timestamp_fields if field in df.columns]
        
        # 添加域名、哈希和端口字段
        domain_fields = ['_source.data.url', '_source.data.win.eventdata.targetUserName', '_source.data.hostname']
        domain_fields = [field for field in domain_fields if field in df.columns]
        
        hash_fields = ['_source.data.win.eventdata.hashes', '_source.data.md5', '_source.data.sha1', '_source.data.sha256']
        hash_fields = [field for field in hash_fields if field in df.columns]
        
        port_fields = ['_source.data.dstport', '_source.data.srcport']
        port_fields = [field for field in port_fields if field in df.columns]
        
        # 添加攻击阶段相关字段
        stage_fields = ['_source.rule.description', '_source.rule.groups', '_source.rule.level']
        stage_fields = [field for field in stage_fields if field in df.columns]
        
        # 打印找到的字段
        print(f"找到的IP字段: {ip_fields}")
        print(f"找到的用户字段: {user_fields}")
        print(f"找到的文件字段: {file_fields}")
        print(f"找到的进程字段: {process_fields}")
        print(f"找到的时间戳字段: {timestamp_fields}")
        print(f"找到的域名字段: {domain_fields}")
        print(f"找到的哈希字段: {hash_fields}")
        print(f"找到的端口字段: {port_fields}")
        print(f"找到的攻击阶段字段: {stage_fields}")
        
        for idx, row in df.iterrows():
            # 提取实体数据
            ips = []
            for field in ip_fields:
                if pd.notna(row.get(field)):
                    ip_value = str(row.get(field)).strip()
                    if ip_value and ip_value.lower() != 'nan':
                        ips.append(ip_value)
            
            users = []
            for field in user_fields:
                if pd.notna(row.get(field)):
                    user_value = str(row.get(field)).strip()
                    if user_value and user_value.lower() != 'nan':
                        users.append(user_value)
            
            files = []
            for field in file_fields:
                if pd.notna(row.get(field)):
                    file_value = str(row.get(field)).strip()
                    if file_value and file_value.lower() != 'nan':
                        files.append(file_value)
            
            processes = []
            for field in process_fields:
                if pd.notna(row.get(field)):
                    process_value = str(row.get(field)).strip()
                    if process_value and process_value.lower() != 'nan':
                        processes.append(process_value)
            
            timestamps = []
            for field in timestamp_fields:
                if pd.notna(row.get(field)):
                    ts_value = str(row.get(field)).strip()
                    if ts_value and ts_value.lower() != 'nan':
                        timestamps.append(ts_value)
            
            domains = []
            for field in domain_fields:
                if pd.notna(row.get(field)):
                    domain_value = str(row.get(field)).strip()
                    if domain_value and domain_value.lower() != 'nan':
                        domains.append(domain_value)
            
            hashes = []
            for field in hash_fields:
                if pd.notna(row.get(field)):
                    hash_value = str(row.get(field)).strip()
                    if hash_value and hash_value.lower() != 'nan':
                        # 处理可能包含多个哈希值的字段
                        if ',' in hash_value:
                            hashes.extend([h.strip() for h in hash_value.split(',') if h.strip()])
                        else:
                            hashes.append(hash_value)
            
            ports = []
            for field in port_fields:
                if pd.notna(row.get(field)):
                    port_value = str(row.get(field)).strip()
                    if port_value and port_value.lower() != 'nan':
                        ports.append(port_value)
            
            attack_stages = []
            for field in stage_fields:
                if pd.notna(row.get(field)):
                    stage_value = str(row.get(field)).strip()
                    if stage_value and stage_value.lower() != 'nan':
                        attack_stages.append(stage_value)
            
            # 创建实体数据结构
            data = {
                'entities': {
                    'ips': ips,
                    'domains': domains,
                    'hashes': hashes,
                    'files': files,
                    'timestamps': timestamps,
                    'processes': processes,
                    'ports': ports,
                    'users': users,
                    'attack_stages': attack_stages
                }
            }
            
            # 只添加有实体数据的记录
            if any(len(entities) > 0 for entities in data['entities'].values()):
                entities_data.append(data)
        
        print(f"成功提取了 {len(entities_data)} 条有效实体数据")
        return entities_data
    except Exception as e:
        print(f"加载Linux APT数据集失败: {e}")
        return None


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
    timestamps = report_data.get('entities', {}).get('timestamps', [])
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
    
    # 记录添加的边数量
    edge_count = 0

    # 添加报告节点
    for i, report in enumerate(entities_data):
        report_node = f"report_{i}"
        G.add_node(report_node, type='report')

        # 提取报告时间
        report_time = extract_report_time(report)
        if report_time:
            time_str = report_time.strftime("%Y-%m-%d")
            # 添加时间戳节点（如果不存在）
            if time_str not in G:
                G.add_node(time_str, type='timestamp')
            # 添加报告与时间戳的边
            G.add_edge(report_node, time_str, type='report_contains_timestamp')
            edge_count += 1

        # 添加IP节点和边
        for ip in report['entities']['ips']:
            if not ip or ip == 'nan':
                continue
            if ip not in G:
                G.add_node(ip, type='ip')
            G.add_edge(report_node, ip, type='report_contains_ip')
            edge_count += 1

        # 添加域名节点和边
        for domain in report['entities']['domains']:
            if not domain or domain == 'nan':
                continue
            if domain not in G:
                G.add_node(domain, type='domain')
            G.add_edge(report_node, domain, type='report_contains_domain')
            edge_count += 1

        # 添加哈希节点和边
        for hash_value in report['entities']['hashes']:
            if not hash_value or hash_value == 'nan':
                continue
            if hash_value not in G:
                G.add_node(hash_value, type='hash')
            G.add_edge(report_node, hash_value, type='report_contains_hash')
            edge_count += 1

        # 添加文件节点和边
        for file_path in report['entities']['files']:
            if not file_path or file_path == 'nan':
                continue
            if file_path not in G:
                G.add_node(file_path, type='file')
            G.add_edge(report_node, file_path, type='report_contains_file')
            edge_count += 1

        # 添加进程节点和边
        for process in report['entities']['processes']:
            if not process or process == 'nan':
                continue
            if process not in G:
                G.add_node(process, type='process')
            G.add_edge(report_node, process, type='report_contains_process')
            edge_count += 1

        # 添加端口节点和边
        for port in report['entities']['ports']:
            if not port:
                continue
            port_str = str(port)
            if port_str not in G:
                G.add_node(port_str, type='port')
            G.add_edge(report_node, port_str, type='report_contains_port')
            edge_count += 1

        # 添加用户节点和边
        for user in report['entities']['users']:
            if not user or user == 'nan':
                continue
            if user not in G:
                G.add_node(user, type='user')
            G.add_edge(report_node, user, type='report_contains_user')
            edge_count += 1

        # 添加攻击阶段节点和边
        for attack_stage in report['entities']['attack_stages']:
            if not attack_stage or attack_stage == 'nan':
                continue
            if attack_stage not in G:
                G.add_node(attack_stage, type='attack_stage')
            G.add_edge(report_node, attack_stage, type='report_describes_attack_stage')
            edge_count += 1

            # 如果有时间戳，将攻击阶段与时间关联
            if report_time:
                G.add_edge(attack_stage, time_str, type='timestamp_of_attack_stage')
                edge_count += 1
                
    print(f"初始节点和边的添加完成，当前边数: {edge_count}")

    # 添加实体之间的关联边
    edge_count_before = edge_count
    for report in entities_data:
        # 获取报告中的所有实体
        ips = [ip for ip in report['entities']['ips'] if ip and ip != 'nan']
        domains = [domain for domain in report['entities']['domains'] if domain and domain != 'nan']
        hashes = [hash_val for hash_val in report['entities']['hashes'] if hash_val and hash_val != 'nan']
        files = [file_path for file_path in report['entities']['files'] if file_path and file_path != 'nan']
        processes = [process for process in report['entities']['processes'] if process and process != 'nan']
        ports = [port for port in report['entities']['ports'] if port]
        users = [user for user in report['entities']['users'] if user and user != 'nan']
        attack_stages = [stage for stage in report['entities']['attack_stages'] if stage and stage != 'nan']

        # 添加实体共现关系
        # IP与其他实体的共现
        for ip in ips:
            for domain in domains:
                if ip in G and domain in G:
                    G.add_edge(ip, domain, type='ip_appears_with_domain')
                    edge_count += 1
            for hash_value in hashes:
                if ip in G and hash_value in G:
                    G.add_edge(ip, hash_value, type='ip_appears_with_hash')
                    edge_count += 1
            for file_path in files:
                if ip in G and file_path in G:
                    G.add_edge(ip, file_path, type='ip_appears_with_file')
                    edge_count += 1
            for port in ports:
                port_str = str(port)
                if ip in G and port_str in G:
                    G.add_edge(ip, port_str, type='ip_uses_port')
                    edge_count += 1
            # IP之间的通信关系（如果有多个IP）
            for other_ip in ips:
                if ip != other_ip and ip in G and other_ip in G:
                    G.add_edge(ip, other_ip, type='ip_communicates_with_ip')
                    edge_count += 1

        # 域名与其他实体的共现
        for domain in domains:
            for hash_value in hashes:
                if domain in G and hash_value in G:
                    G.add_edge(domain, hash_value, type='domain_appears_with_hash')
                    edge_count += 1
            for file_path in files:
                if domain in G and file_path in G:
                    G.add_edge(domain, file_path, type='domain_appears_with_file')
                    edge_count += 1
            # 域名解析到IP
            for ip in ips:
                if domain in G and ip in G:
                    G.add_edge(domain, ip, type='domain_resolves_to_ip')
                    edge_count += 1

        # 哈希与文件的共现
        for hash_value in hashes:
            for file_path in files:
                if hash_value in G and file_path in G:
                    G.add_edge(hash_value, file_path, type='hash_appears_with_file')
                    edge_count += 1

        # 进程关系
        for i, process in enumerate(processes):
            # 进程与文件的关系
            for file_path in files:
                if process in G and file_path in G:
                    G.add_edge(process, file_path, type='process_accesses_file')
                    edge_count += 1
            # 进程与IP的关系
            for ip in ips:
                if process in G and ip in G:
                    G.add_edge(process, ip, type='process_connects_to_ip')
                    edge_count += 1
            # 进程与端口的关系
            for port in ports:
                port_str = str(port)
                if process in G and port_str in G:
                    G.add_edge(process, port_str, type='process_uses_port')
                    edge_count += 1
            # 进程之间的父子关系（如果有多个进程，假设按顺序有父子关系）
            if i < len(processes) - 1 and process in G and processes[i + 1] in G:
                G.add_edge(process, processes[i + 1], type='process_creates_process')
                edge_count += 1

        # 用户关系
        for user in users:
            # 用户与进程的关系
            for process in processes:
                if user in G and process in G:
                    G.add_edge(user, process, type='user_owns_process')
                    edge_count += 1
            # 用户与文件的关系
            for file_path in files:
                if user in G and file_path in G:
                    G.add_edge(user, file_path, type='user_accesses_file')
                    edge_count += 1

        # 攻击阶段关系
        for i, attack_stage in enumerate(attack_stages):
            # 攻击阶段之间的顺序关系
            if i < len(attack_stages) - 1 and attack_stage in G and attack_stages[i + 1] in G:
                G.add_edge(attack_stage, attack_stages[i + 1], type='attack_stage_follows')
                edge_count += 1
            # 攻击阶段与实体的关系
            for ip in ips:
                if attack_stage in G and ip in G:
                    G.add_edge(attack_stage, ip, type='attack_stage_involves_ip')
                    edge_count += 1
            for domain in domains:
                if attack_stage in G and domain in G:
                    G.add_edge(attack_stage, domain, type='attack_stage_involves_domain')
                    edge_count += 1
            for file_path in files:
                if attack_stage in G and file_path in G:
                    G.add_edge(attack_stage, file_path, type='attack_stage_involves_file')
                    edge_count += 1
            for process in processes:
                if attack_stage in G and process in G:
                    G.add_edge(attack_stage, process, type='attack_stage_involves_process')
                    edge_count += 1
    
    print(f"实体关系边添加完成，添加了 {edge_count - edge_count_before} 条关系边")
    return G

<<<<<<< Updated upstream
# 将NetworkX图转换为DGL异构图
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
        start_time = min_time + timedelta(days=i * interval)
        end_time = min_time + timedelta(days=(i + 1) * interval)

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
# 可视化图
def visualize_graph(graph, title="APT实体关系图", output_file="apt_graph.png"):
    plt.figure(figsize=(15, 12))

    # 设置中文字体支持
    plt.rcParams['font.sans-serif'] = ['SimHei', 'FangSong', 'Microsoft YaHei', 'DejaVu Sans']
    plt.rcParams['axes.unicode_minus'] = False

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
    pos = nx.spring_layout(graph, seed=42, k=0.5)

    # 绘制节点
    nx.draw_networkx_nodes(graph, pos, node_color=node_colors, alpha=0.8, node_size=50)

    # 绘制边（减少箭头大小以提高性能）
    nx.draw_networkx_edges(graph, pos, alpha=0.3, arrows=True, arrowsize=10, width=0.3)

    # 添加标题
    plt.title(title, fontsize=16)

    # 添加图例（固定位置以提高性能）
    legend_elements = []
    for node_type, color in color_map.items():
        legend_elements.append(plt.Line2D([0], [0], marker='o', color='w',
                                          markerfacecolor=color, markersize=8, label=node_type))
    plt.legend(handles=legend_elements, loc='upper right')

    # 关闭坐标轴
    plt.axis('off')

    # 保存图像
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()

# 主函数
def main():
    print("加载实体数据...")
    entities_data = load_entities()
    
    print(f"共加载了 {len(entities_data)} 个报告的实体数据")
    
    print("构建异构图...")
    nx_graph = build_heterogeneous_graph(entities_data)
    
    print(f"图构建完成，包含 {nx_graph.number_of_nodes()} 个节点和 {nx_graph.number_of_edges()} 条边")
    
=======

# 将NetworkX图转换为节点和边的统计信息
def analyze_graph_structure(nx_graph):
>>>>>>> Stashed changes
    # 统计各类型节点的数量
    node_type_counts = {}
    for _, data in nx_graph.nodes(data=True):
        node_type = data.get('type', 'unknown')
        node_type_counts[node_type] = node_type_counts.get(node_type, 0) + 1
<<<<<<< Updated upstream
    
    print("节点类型统计:")
    for node_type, count in node_type_counts.items():
        print(f"  {node_type}: {count}")
    
=======

>>>>>>> Stashed changes
    # 统计各类型边的数量
    edge_type_counts = {}
    for _, _, data in nx_graph.edges(data=True):
        edge_type = data.get('type', 'unknown')
        edge_type_counts[edge_type] = edge_type_counts.get(edge_type, 0) + 1
<<<<<<< Updated upstream
    
    print("边类型统计:")
    for edge_type, count in edge_type_counts.items():
        print(f"  {edge_type}: {count}")
    
    print("可视化图...")
    visualize_graph(nx_graph)
    
    print("转换为DGL异构图...")
    dgl_graph, node_maps = convert_to_dgl_graph(nx_graph)
    
    print("创建时序快照...")
    snapshots = create_temporal_snapshots(nx_graph)
    
    print(f"创建了 {len(snapshots)} 个时序快照")
    
    # 保存DGL图
    if snapshots:
        print("保存时序异构图...")
        dgl.save_graphs(output_graph_file, snapshots)
        print(f"时序异构图已保存到 {output_graph_file}")
    else:
        print("警告: 没有创建任何时序快照，可能是因为缺少时间信息")
=======

    return node_type_counts, edge_type_counts


# 将图按时间划分为多个快照
def create_temporal_snapshots(nx_graph, num_snapshots=5, time_granularity='day'):
    # 获取所有带有时间戳的节点
    timestamp_nodes = [node for node, data in nx_graph.nodes(data=True) if data.get('type') == 'timestamp']

    if not timestamp_nodes:
        print("警告: 没有找到时间戳节点")
        return []

    # 根据时间粒度解析时间戳
    if time_granularity == 'day':
        timestamps = []
        for ts in timestamp_nodes:
            try:
                timestamps.append(datetime.strptime(ts, "%Y-%m-%d"))
            except ValueError:
                continue
    elif time_granularity == 'month':
        timestamps = []
        for ts in timestamp_nodes:
            try:
                timestamps.append(datetime.strptime(ts[:7], "%Y-%m"))
            except ValueError:
                continue
    elif time_granularity == 'year':
        timestamps = []
        for ts in timestamp_nodes:
            try:
                timestamps.append(datetime.strptime(ts[:4], "%Y"))
            except ValueError:
                continue
    else:
        timestamps = []
        for ts in timestamp_nodes:
            try:
                timestamps.append(datetime.strptime(ts, "%Y-%m-%d"))
            except ValueError:
                continue

    if not timestamps:
        print("警告: 没有有效的时间戳")
        return []

    sorted_timestamps = sorted(timestamps)

    # 计算时间范围
    min_time = sorted_timestamps[0]
    max_time = sorted_timestamps[-1]

    if time_granularity == 'day':
        time_range = (max_time - min_time).days
    elif time_granularity == 'month':
        time_range = (max_time.year - min_time.year) * 12 + (max_time.month - min_time.month)
    elif time_granularity == 'year':
        time_range = max_time.year - min_time.year
    else:
        time_range = (max_time - min_time).days

    if time_range == 0:
        time_range = 1  # 避免除以零

    # 计算每个快照的时间间隔
    interval = time_range / num_snapshots

    # 创建快照
    snapshots = []
    for i in range(num_snapshots):
        # 计算快照的时间范围
        if time_granularity == 'day':
            start_time = min_time + datetime.timedelta(days=int(i * interval))
            end_time = min_time + datetime.timedelta(days=int((i + 1) * interval))
        elif time_granularity == 'month':
            start_month = min_time.month + int(i * interval)
            start_year = min_time.year + start_month // 12
            start_month = start_month % 12 + 1
            start_time = datetime(start_year, start_month, 1)

            end_month = min_time.month + int((i + 1) * interval)
            end_year = min_time.year + end_month // 12
            end_month = end_month % 12 + 1
            end_time = datetime(end_year, end_month, 1)
        elif time_granularity == 'year':
            start_time = datetime(min_time.year + int(i * interval), 1, 1)
            end_time = datetime(min_time.year + int((i + 1) * interval), 1, 1)
        else:
            start_time = min_time + datetime.timedelta(days=int(i * interval))
            end_time = min_time + datetime.timedelta(days=int((i + 1) * interval))

        # 筛选在该时间范围内的时间戳节点
        snapshot_timestamps = []
        for ts in sorted_timestamps:
            if time_granularity == 'day':
                if start_time <= ts < end_time:
                    snapshot_timestamps.append(ts.strftime("%Y-%m-%d"))
            elif time_granularity == 'month':
                ts_month = datetime(ts.year, ts.month, 1)
                if start_time <= ts_month < end_time:
                    snapshot_timestamps.append(ts.strftime("%Y-%m-%d"))
            elif time_granularity == 'year':
                ts_year = datetime(ts.year, 1, 1)
                if start_time <= ts_year < end_time:
                    snapshot_timestamps.append(ts.strftime("%Y-%m-%d"))
            else:
                if start_time <= ts < end_time:
                    snapshot_timestamps.append(ts.strftime("%Y-%m-%d"))

        # 创建子图
        subgraph = nx.DiGraph()

        # 添加时间戳节点及其关联的报告节点
        for ts in snapshot_timestamps:
            # 精确匹配日期
            ts_nodes = [n for n in timestamp_nodes if n == ts]

            for ts_node in ts_nodes:
                subgraph.add_node(ts_node, **nx_graph.nodes[ts_node])
                # 获取与该时间戳相关的报告
                for pred in nx_graph.predecessors(ts_node):
                    if nx_graph.nodes[pred].get('type') == 'report':
                        # 添加报告节点
                        subgraph.add_node(pred, **nx_graph.nodes[pred])
                        # 添加报告到时间戳的边
                        edge_data = nx_graph.get_edge_data(pred, ts_node)
                        if edge_data:
                            subgraph.add_edge(pred, ts_node, **edge_data)

                        # 添加报告关联的所有实体节点和边
                        for succ in nx_graph.successors(pred):
                            node_type = nx_graph.nodes[succ].get('type')
                            if node_type in ['ip', 'domain', 'hash', 'file', 'process', 'port', 'user', 'attack_stage']:
                                # 添加实体节点
                                subgraph.add_node(succ, **nx_graph.nodes[succ])
                                # 添加报告到实体的边
                                edge_data = nx_graph.get_edge_data(pred, succ)
                                if edge_data:
                                    subgraph.add_edge(pred, succ, **edge_data)

        # 添加实体之间的关联边
        for node in list(subgraph.nodes()):
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
            except Exception as e:
                print(f"转换子图时出错: {e}")

    return snapshots


# 可视化图
def visualize_graph(graph, title="APT实体关系图", output_file="apt_graph.png"):
    print(f"图太大（{graph.number_of_nodes()}个节点和{graph.number_of_edges()}条边），只可视化一个子图样本")
    
    # 从图中随机选择一个小的子图进行可视化
    # 首先选择一些报告节点作为起点
    report_nodes = [n for n, d in graph.nodes(data=True) if d.get('type') == 'report']
    
    # 如果报告节点太多，只取前100个
    if len(report_nodes) > 100:
        import random
        random.seed(42)  # 设置随机种子以确保结果可重现
        sample_reports = random.sample(report_nodes, 100)
    else:
        sample_reports = report_nodes
    
    # 创建一个子图，包含这些报告节点和它们的邻居
    subgraph_nodes = set(sample_reports)
    for report in sample_reports:
        subgraph_nodes.update(graph.neighbors(report))
    
    # 如果子图仍然太大，进一步限制节点数量
    if len(subgraph_nodes) > 500:
        subgraph_nodes = list(subgraph_nodes)[:500]
    
    # 创建子图
    subgraph = graph.subgraph(subgraph_nodes)
    print(f"创建了一个包含{subgraph.number_of_nodes()}个节点和{subgraph.number_of_edges()}条边的子图进行可视化")
    
    try:
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
        node_colors = [color_map.get(subgraph.nodes[node].get('type'), 'gray') for node in subgraph.nodes()]

        # 使用更高效的布局算法
        pos = nx.kamada_kawai_layout(subgraph)

        # 绘制节点
        nx.draw_networkx_nodes(subgraph, pos, node_color=node_colors, alpha=0.8, node_size=80)

        # 绘制边
        nx.draw_networkx_edges(subgraph, pos, alpha=0.4, arrows=True, width=0.5)

        # 添加标题
        plt.title(title)

        # 添加图例
        for node_type, color in color_map.items():
            plt.plot([], [], 'o', color=color, label=node_type)
        plt.legend()

        # 保存图像
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"图像已保存为{output_file}")
    except Exception as e:
        print(f"可视化图时出错: {e}")
        print("跳过可视化步骤，继续执行后续操作")


# 主函数
def main():
    print("加载实体数据...")
    entities_data = load_entities()

    if entities_data is None:
        print("无法加载实体数据，程序退出")
        return

    print(f"共加载了 {len(entities_data)} 个报告的实体数据")

    print("构建异构图...")
    nx_graph = build_heterogeneous_graph(entities_data)

    print(f"图构建完成，包含 {nx_graph.number_of_nodes()} 个节点和 {nx_graph.number_of_edges()} 条边")

    # 使用新的分析函数获取节点和边的统计信息
    node_type_counts, edge_type_counts = analyze_graph_structure(nx_graph)

    print("节点类型统计:")
    for node_type, count in node_type_counts.items():
        print(f"{node_type}: {count}")

    print("边类型统计:")
    for edge_type, count in edge_type_counts.items():
        print(f"{edge_type}: {count}")

    print("可视化图...")
    visualize_graph(nx_graph)

    # 保存NetworkX图
    print("保存NetworkX图...")
    nx.write_graphml(nx_graph, "apt_graph.graphml")
    print("图已保存为GraphML格式")

>>>>>>> Stashed changes

if __name__ == "__main__":
    main()