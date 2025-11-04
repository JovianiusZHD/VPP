import os
import pandas as pd
import json
import re

def separate_vulns_and_patches(df):
    """拆分为漏洞函数和补丁函数"""
    patches = df.drop('vulnerable_func', axis=1)
    patches = patches.rename(columns={'patched_func': 'func'})
    patches["target"] = 0

    vulns = df.drop('patched_func', axis=1)
    vulns = vulns.rename(columns={'vulnerable_func': 'func'})
    vulns["target"] = 1

    fused_df = pd.concat([patches, vulns], ignore_index=True)
    return fused_df


def extract_func_name(code_str):
    """提取函数名"""
    match = re.search(r'\b([A-Za-z_]\w*)\s*\(', code_str)
    if match:
        return match.group(1)
    return "unknown_func"


def df_to_nested_json(df):
    """转换为嵌套 JSON"""
    nested = {}
    for _, row in df.iterrows():
        # 选择正确路径
        filepath = row['vulnerable_filepath'] if row['target'] == 1 else row['patched_filepath']
        code_str = row['func']
        label = int(row['target'])
        funcname = extract_func_name(code_str)

        # 确保路径存在
        if filepath not in nested:
            nested[filepath] = {}

        # 根据标签添加后缀
        if label == 1:
            func_key = f"{funcname}_vuln"
        else:
            func_key = f"{funcname}_patch"

        nested[filepath][func_key] = {
            "code": code_str,
            "label": label
        }
    return nested


# =========== 主程序 ===========

base_dir = os.path.dirname(__file__)
output_dir = os.path.join(base_dir, 'nest-output')
os.makedirs(output_dir, exist_ok=True)

# 读取原始 JSON
vpp_train = pd.read_json(os.path.join(base_dir, 'VulnPatchPairs-Train.json'))
vpp_valid = pd.read_json(os.path.join(base_dir, 'VulnPatchPairs-Valid.json'))
vpp_test  = pd.read_json(os.path.join(base_dir, 'VulnPatchPairs-Test.json'))

# 拆分
vpp_train = separate_vulns_and_patches(vpp_train)
vpp_valid = separate_vulns_and_patches(vpp_valid)
vpp_test  = separate_vulns_and_patches(vpp_test)

# 转换为嵌套 JSON
train_json = df_to_nested_json(vpp_train)
valid_json = df_to_nested_json(vpp_valid)
test_json  = df_to_nested_json(vpp_test)

# 保存为 JSON 文件
with open(os.path.join(output_dir, 'vpp_train_nested.json'), 'w', encoding='utf-8') as f:
    json.dump(train_json, f, ensure_ascii=False, indent=2)

with open(os.path.join(output_dir, 'vpp_valid_nested.json'), 'w', encoding='utf-8') as f:
    json.dump(valid_json, f, ensure_ascii=False, indent=2)

with open(os.path.join(output_dir, 'vpp_test_nested.json'), 'w', encoding='utf-8') as f:
    json.dump(test_json, f, ensure_ascii=False, indent=2)

print(f"✅ Nested JSON files saved in: {output_dir}")
