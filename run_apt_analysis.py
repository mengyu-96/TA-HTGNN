import os
import subprocess
import time
import argparse

def run_command(command, description):
    print(f"\n{'='*80}")
    print(f"开始{description}...")
    print(f"{'='*80}")
    
    start_time = time.time()
    process = subprocess.Popen(command, shell=True)
    process.wait()
    end_time = time.time()
    
    if process.returncode == 0:
        print(f"\n{description}成功完成！耗时: {end_time - start_time:.2f}秒")
        return True
    else:
        print(f"\n{description}失败，返回代码: {process.returncode}")
        return False

def main():
    parser = argparse.ArgumentParser(description='APT时序异构图分析流程')
    parser.add_argument('--skip-build', action='store_true', help='跳过构建实体关系图步骤')
    parser.add_argument('--skip-integrate', action='store_true', help='跳过整合Linux APT数据步骤')
    parser.add_argument('--skip-model', action='store_true', help='跳过模型训练步骤')
    args = parser.parse_args()
    
    print("\n欢迎使用APT时序异构图分析工具！")
    print("本工具将执行以下步骤：")
    print("1. 构建APT实体关系图")
    print("2. 整合Linux APT数据集")
    print("3. 训练HTGNN模型")
    
    # 检查必要文件是否存在
    required_files = [
        "APTnotes-tools/reports_entities.jsonl",
        "Linux-APT-Dataset/Linux-APT-Dataset-2024/combine.csv"
    ]
    
    for file_path in required_files:
        if not os.path.exists(file_path):
            print(f"错误: 找不到必要的文件 {file_path}")
            print("请确保所有数据文件都已准备好")
            return
    
    # 步骤1: 构建APT实体关系图
    if not args.skip_build:
        if not run_command("python build_entity_relations.py", "构建APT实体关系图"):
            print("由于构建APT实体关系图失败，流程终止")
            return
    else:
        print("\n跳过构建APT实体关系图步骤")
    
    # 步骤2: 整合Linux APT数据集
    if not args.skip_integrate:
        if not run_command("python integrate_linux_apt_data.py", "整合Linux APT数据集"):
            print("由于整合Linux APT数据集失败，流程终止")
            return
    else:
        print("\n跳过整合Linux APT数据集步骤")
    
    # 步骤3: 训练HTGNN模型
    if not args.skip_model:
        if not run_command("python adapt_htgnn_model.py", "训练HTGNN模型"):
            print("训练HTGNN模型失败")
            return
    else:
        print("\n跳过训练HTGNN模型步骤")
    
    print("\n所有步骤已完成！")
    print("\n结果文件:")
    print("- APT实体关系图: apt_graph.png")
    print("- 时序异构图: apt_temporal_graph.bin")
    print("- 集成APT实体关系图: integrated_apt_graph.png")
    print("- 集成时序异构图: integrated_apt_temporal_graph.bin")
    print("- HTGNN模型: apt_htgnn_model.pt")
    print("- 模型结果: apt_htgnn_results.json")
    print("- 节点分类结果可视化: node_classification_results.png")
    print("- 链接预测结果可视化: link_prediction_results.png")

if __name__ == "__main__":
    main()