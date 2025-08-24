import os
import json
import dgl
import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import roc_auc_score, precision_recall_curve, auc
from HTGNN.model.model import HTGNN, NodePredictor, LinkPredictor

# 文件路径
input_graph_file = "integrated_apt_temporal_graph.bin"
output_model_file = "apt_htgnn_model.pt"
output_results_file = "apt_htgnn_results.json"

# 模型参数
class ModelConfig:
    def __init__(self):
        self.hidden_dim = 64
        self.num_heads = 4
        self.num_layers = 2
        self.dropout = 0.2
        self.lr = 0.001
        self.weight_decay = 1e-5
        self.epochs = 100
        self.patience = 10
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.time_aware = True  # 启用时间感知功能
        self.temporal_embedding_dim = 16  # 时间嵌入维度

# 加载时序异构图
def load_temporal_graph():
    try:
        graphs, _ = dgl.load_graphs(input_graph_file)
        print(f"成功加载时序异构图，共{len(graphs)}个时间快照")
        return graphs
    except Exception as e:
        print(f"加载时序异构图失败: {e}")
        return None

# 准备训练数据
def prepare_data(graphs, config):
    # 获取节点类型
    node_types = list(graphs[0].ntypes)
    print(f"图中的节点类型: {node_types}")
    
    # 获取边类型
    edge_types = list(graphs[0].etypes)
    print(f"图中的边类型: {edge_types}")
    
    # 将图移动到指定设备
    device_graphs = []
    for g in graphs:
        device_g = g.to(config.device)
        # 为每种节点类型添加特征（如果没有）
        for ntype in device_g.ntypes:
            if 'feat' not in device_g.nodes[ntype].data:
                num_nodes = device_g.num_nodes(ntype)
                # 使用随机特征初始化
                device_g.nodes[ntype].data['feat'] = torch.randn(num_nodes, config.hidden_dim).to(config.device)
        device_graphs.append(device_g)
    
    # 划分训练集、验证集和测试集
    num_snapshots = len(device_graphs)
    if num_snapshots >= 3:
        train_graphs = device_graphs[:int(num_snapshots*0.6)]
        val_graphs = device_graphs[int(num_snapshots*0.6):int(num_snapshots*0.8)]
        test_graphs = device_graphs[int(num_snapshots*0.8):]
    else:
        # 如果快照数量不足，使用最后一个快照进行内部划分
        train_graphs = device_graphs[:-1] if num_snapshots > 1 else device_graphs
        val_graphs = [device_graphs[-1]]
        test_graphs = [device_graphs[-1]]
        
        # 在最后一个快照中划分节点和边
        last_graph = device_graphs[-1]
        for ntype in last_graph.ntypes:
            num_nodes = last_graph.num_nodes(ntype)
            if num_nodes > 0:
                # 创建训练/验证/测试掩码
                train_mask = torch.zeros(num_nodes, dtype=torch.bool)
                val_mask = torch.zeros(num_nodes, dtype=torch.bool)
                test_mask = torch.zeros(num_nodes, dtype=torch.bool)
                
                # 随机划分
                indices = torch.randperm(num_nodes)
                train_size = int(num_nodes * 0.6)
                val_size = int(num_nodes * 0.2)
                
                train_mask[indices[:train_size]] = True
                val_mask[indices[train_size:train_size+val_size]] = True
                test_mask[indices[train_size+val_size:]] = True
                
                # 将掩码添加到图中
                last_graph.nodes[ntype].data['train_mask'] = train_mask
                last_graph.nodes[ntype].data['val_mask'] = val_mask
                last_graph.nodes[ntype].data['test_mask'] = test_mask
    
    return train_graphs, val_graphs, test_graphs, node_types, edge_types

# 构建HTGNN模型
def build_model(graphs, node_types, edge_types, config):
    # 获取节点特征维度
    in_dims = {}
    for ntype in node_types:
        if graphs[0].num_nodes(ntype) > 0:
            in_dims[ntype] = graphs[0].nodes[ntype].data['feat'].shape[1]
        else:
            in_dims[ntype] = config.hidden_dim
    
    # 如果启用时间感知功能，调整输入维度
    if config.time_aware:
        for ntype in in_dims:
            in_dims[ntype] += config.temporal_embedding_dim
    
    # 创建HTGNN模型
    model = HTGNN(
        in_dims=in_dims,
        hidden_dim=config.hidden_dim,
        num_classes=config.hidden_dim,  # 输出维度与隐藏层相同
        num_layers=config.num_layers,
        num_heads=config.num_heads,
        dropout=config.dropout,
        node_types=node_types,
        edge_types=edge_types
    ).to(config.device)
    
    # 创建节点预测器
    node_predictor = NodePredictor(
        in_dim=config.hidden_dim,
        hidden_dim=config.hidden_dim // 2,
        num_classes=2,  # 二分类任务
        dropout=config.dropout
    ).to(config.device)
    
    # 创建链接预测器
    link_predictor = LinkPredictor(
        in_dim=config.hidden_dim,
        hidden_dim=config.hidden_dim // 2,
        num_classes=1,  # 二分类任务
        dropout=config.dropout
    ).to(config.device)
    
    return model, node_predictor, link_predictor

# 训练模型
def train_model(model, node_predictor, link_predictor, train_graphs, val_graphs, config):
    # 优化器
    optimizer = torch.optim.Adam(
        list(model.parameters()) + 
        list(node_predictor.parameters()) + 
        list(link_predictor.parameters()),
        lr=config.lr,
        weight_decay=config.weight_decay
    )
    
    # 早停
    best_val_loss = float('inf')
    patience_counter = 0
    best_model_state = None
    best_node_predictor_state = None
    best_link_predictor_state = None
    
    # 训练循环
    for epoch in range(config.epochs):
        # 训练模式
        model.train()
        node_predictor.train()
        link_predictor.train()
        
        train_loss = 0
        
        # 对每个时间快照进行训练
        for t, g in enumerate(train_graphs):
            optimizer.zero_grad()
            
            # 获取节点嵌入
            embeddings = model(g)
            
            # 节点分类损失（以'report'节点为例）
            node_loss = 0
            for ntype in g.ntypes:
                if g.num_nodes(ntype) > 0 and 'train_mask' in g.nodes[ntype].data:
                    train_mask = g.nodes[ntype].data['train_mask']
                    if train_mask.sum() > 0:
                        # 这里假设我们有标签，实际中需要根据任务设置标签
                        # 这里使用随机标签作为示例
                        labels = torch.randint(0, 2, (train_mask.sum(),)).to(config.device)
                        logits = node_predictor(embeddings[ntype][train_mask])
                        node_loss += F.cross_entropy(logits, labels)
            
            # 链接预测损失
            link_loss = 0
            for etype in g.etypes:
                src_type, _, dst_type = g.to_canonical_etype(etype)
                if g.num_edges(etype) > 0:
                    # 采样正样本
                    pos_edges = torch.randint(0, g.num_edges(etype), (100,))
                    src, dst = g.find_edges(pos_edges, etype=etype)
                    pos_score = link_predictor(embeddings[src_type][src], embeddings[dst_type][dst])
                    pos_loss = -torch.log(torch.sigmoid(pos_score) + 1e-15).mean()
                    
                    # 采样负样本
                    neg_src = torch.randint(0, g.num_nodes(src_type), (100,)).to(config.device)
                    neg_dst = torch.randint(0, g.num_nodes(dst_type), (100,)).to(config.device)
                    neg_score = link_predictor(embeddings[src_type][neg_src], embeddings[dst_type][neg_dst])
                    neg_loss = -torch.log(1 - torch.sigmoid(neg_score) + 1e-15).mean()
                    
                    link_loss += pos_loss + neg_loss
            
            # 总损失
            loss = node_loss + link_loss
            loss.backward()
            optimizer.step()
            
            train_loss += loss.item()
        
        train_loss /= len(train_graphs)
        
        # 验证
        val_loss = evaluate(model, node_predictor, link_predictor, val_graphs, config)
        
        print(f"Epoch {epoch+1}/{config.epochs}, Train Loss: {train_loss:.4f}, Val Loss: {val_loss:.4f}")
        
        # 早停检查
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            # 保存最佳模型状态
            best_model_state = model.state_dict()
            best_node_predictor_state = node_predictor.state_dict()
            best_link_predictor_state = link_predictor.state_dict()
        else:
            patience_counter += 1
            if patience_counter >= config.patience:
                print(f"Early stopping at epoch {epoch+1}")
                break
    
    # 加载最佳模型状态
    if best_model_state is not None:
        model.load_state_dict(best_model_state)
        node_predictor.load_state_dict(best_node_predictor_state)
        link_predictor.load_state_dict(best_link_predictor_state)
    
    return model, node_predictor, link_predictor

# 评估模型
def evaluate(model, node_predictor, link_predictor, graphs, config):
    model.eval()
    node_predictor.eval()
    link_predictor.eval()
    
    val_loss = 0
    
    with torch.no_grad():
        for g in graphs:
            # 获取节点嵌入
            embeddings = model(g)
            
            # 节点分类损失
            node_loss = 0
            for ntype in g.ntypes:
                if g.num_nodes(ntype) > 0 and 'val_mask' in g.nodes[ntype].data:
                    val_mask = g.nodes[ntype].data['val_mask']
                    if val_mask.sum() > 0:
                        # 这里假设我们有标签，实际中需要根据任务设置标签
                        labels = torch.randint(0, 2, (val_mask.sum(),)).to(config.device)
                        logits = node_predictor(embeddings[ntype][val_mask])
                        node_loss += F.cross_entropy(logits, labels)
            
            # 链接预测损失
            link_loss = 0
            for etype in g.etypes:
                src_type, _, dst_type = g.to_canonical_etype(etype)
                if g.num_edges(etype) > 0:
                    # 采样正样本
                    pos_edges = torch.randint(0, g.num_edges(etype), (100,))
                    src, dst = g.find_edges(pos_edges, etype=etype)
                    pos_score = link_predictor(embeddings[src_type][src], embeddings[dst_type][dst])
                    pos_loss = -torch.log(torch.sigmoid(pos_score) + 1e-15).mean()
                    
                    # 采样负样本
                    neg_src = torch.randint(0, g.num_nodes(src_type), (100,)).to(config.device)
                    neg_dst = torch.randint(0, g.num_nodes(dst_type), (100,)).to(config.device)
                    neg_score = link_predictor(embeddings[src_type][neg_src], embeddings[dst_type][neg_dst])
                    neg_loss = -torch.log(1 - torch.sigmoid(neg_score) + 1e-15).mean()
                    
                    link_loss += pos_loss + neg_loss
            
            # 总损失
            loss = node_loss + link_loss
            val_loss += loss.item()
    
    val_loss /= len(graphs)
    return val_loss

# 测试模型
def test_model(model, node_predictor, link_predictor, test_graphs, node_types, edge_types, config):
    model.eval()
    node_predictor.eval()
    link_predictor.eval()
    
    results = {
        'node_classification': {},
        'link_prediction': {}
    }
    
    with torch.no_grad():
        for t, g in enumerate(test_graphs):
            # 获取节点嵌入
            embeddings = model(g)
            
            # 节点分类评估
            for ntype in node_types:
                if g.num_nodes(ntype) > 0 and 'test_mask' in g.nodes[ntype].data:
                    test_mask = g.nodes[ntype].data['test_mask']
                    if test_mask.sum() > 0:
                        # 这里假设我们有标签，实际中需要根据任务设置标签
                        labels = torch.randint(0, 2, (test_mask.sum(),)).to(config.device)
                        logits = node_predictor(embeddings[ntype][test_mask])
                        preds = torch.argmax(logits, dim=1)
                        accuracy = (preds == labels).float().mean().item()
                        
                        if ntype not in results['node_classification']:
                            results['node_classification'][ntype] = []
                        results['node_classification'][ntype].append({
                            'snapshot': t,
                            'accuracy': accuracy
                        })
            
            # 链接预测评估
            for etype in edge_types:
                canonical_etype = g.to_canonical_etype(etype) if isinstance(etype, str) else etype
                src_type, edge_type, dst_type = canonical_etype
                
                if g.num_edges(etype) > 0:
                    # 采样正样本
                    num_pos = min(100, g.num_edges(etype))
                    pos_edges = torch.randint(0, g.num_edges(etype), (num_pos,))
                    src, dst = g.find_edges(pos_edges, etype=etype)
                    pos_score = link_predictor(embeddings[src_type][src], embeddings[dst_type][dst])
                    
                    # 采样负样本
                    neg_src = torch.randint(0, g.num_nodes(src_type), (num_pos,)).to(config.device)
                    neg_dst = torch.randint(0, g.num_nodes(dst_type), (num_pos,)).to(config.device)
                    neg_score = link_predictor(embeddings[src_type][neg_src], embeddings[dst_type][neg_dst])
                    
                    # 计算AUC
                    scores = torch.cat([pos_score, neg_score]).cpu().numpy()
                    labels = torch.cat([torch.ones(num_pos), torch.zeros(num_pos)]).cpu().numpy()
                    auc_score = roc_auc_score(labels, scores)
                    
                    # 计算AP
                    precision, recall, _ = precision_recall_curve(labels, scores)
                    ap_score = auc(recall, precision)
                    
                    if etype not in results['link_prediction']:
                        results['link_prediction'][etype] = []
                    results['link_prediction'][etype].append({
                        'snapshot': t,
                        'auc': auc_score,
                        'ap': ap_score
                    })
    
    return results

# 保存模型和结果
def save_model_and_results(model, node_predictor, link_predictor, results):
    # 保存模型
    torch.save({
        'model': model.state_dict(),
        'node_predictor': node_predictor.state_dict(),
        'link_predictor': link_predictor.state_dict()
    }, output_model_file)
    print(f"模型已保存到 {output_model_file}")
    
    # 保存结果
    with open(output_results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"结果已保存到 {output_results_file}")

# 可视化结果
def visualize_results(results):
    # 节点分类结果可视化
    if results['node_classification']:
        plt.figure(figsize=(10, 6))
        for ntype, metrics in results['node_classification'].items():
            snapshots = [m['snapshot'] for m in metrics]
            accuracies = [m['accuracy'] for m in metrics]
            plt.plot(snapshots, accuracies, marker='o', label=f'{ntype}')
        
        plt.xlabel('时间快照')
        plt.ylabel('准确率')
        plt.title('节点分类准确率随时间变化')
        plt.legend()
        plt.grid(True)
        plt.savefig('node_classification_results.png')
        plt.close()
    
    # 链接预测结果可视化
    if results['link_prediction']:
        plt.figure(figsize=(12, 8))
        for i, (etype, metrics) in enumerate(results['link_prediction'].items()):
            snapshots = [m['snapshot'] for m in metrics]
            aucs = [m['auc'] for m in metrics]
            aps = [m['ap'] for m in metrics]
            
            plt.subplot(2, 1, 1)
            plt.plot(snapshots, aucs, marker='o', label=f'{etype}')
            plt.ylabel('AUC')
            plt.title('链接预测AUC随时间变化')
            plt.grid(True)
            
            plt.subplot(2, 1, 2)
            plt.plot(snapshots, aps, marker='s', label=f'{etype}')
            plt.xlabel('时间快照')
            plt.ylabel('AP')
            plt.title('链接预测AP随时间变化')
            plt.grid(True)
        
        plt.tight_layout()
        plt.legend()
        plt.savefig('link_prediction_results.png')
        plt.close()

# 主函数
def main():
    # 加载配置
    config = ModelConfig()
    print(f"使用设备: {config.device}")
    
    # 加载时序异构图
    graphs = load_temporal_graph()
    if graphs is None or len(graphs) == 0:
        print("无法继续，时序异构图加载失败或为空")
        return
    
    # 准备数据
    train_graphs, val_graphs, test_graphs, node_types, edge_types = prepare_data(graphs, config)
    print(f"训练集: {len(train_graphs)}个快照, 验证集: {len(val_graphs)}个快照, 测试集: {len(test_graphs)}个快照")
    
    # 构建模型
    model, node_predictor, link_predictor = build_model(graphs, node_types, edge_types, config)
    print("模型构建完成")
    
    # 训练模型
    print("开始训练模型...")
    model, node_predictor, link_predictor = train_model(
        model, node_predictor, link_predictor, train_graphs, val_graphs, config
    )
    print("模型训练完成")
    
    # 测试模型
    print("开始测试模型...")
    results = test_model(model, node_predictor, link_predictor, test_graphs, node_types, edge_types, config)
    
    # 保存模型和结果
    save_model_and_results(model, node_predictor, link_predictor, results)
    
    # 可视化结果
    visualize_results(results)
    print("结果可视化完成")

if __name__ == "__main__":
    main()