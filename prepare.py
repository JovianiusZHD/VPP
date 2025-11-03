import os
import pandas as pd

def separate_vulns_and_patches(df):
    patches = df.drop('vulnerable_func', axis=1)
    patches = patches.rename(columns={'patched_func': 'func'})
    patches["target"] = 0

    vulns = df.drop('patched_func', axis=1)
    vulns = vulns.rename(columns={'vulnerable_func': 'func'})
    vulns["target"] = 1

    fused_df = pd.concat([patches, vulns], ignore_index=True)
    return fused_df

# 当前脚本所在目录
base_dir = os.path.dirname(__file__)

# 创建输出目录
output_dir = os.path.join(base_dir, 'output')
os.makedirs(output_dir, exist_ok=True)

# 读取原始 JSON
vpp_train = pd.read_json(os.path.join(base_dir, 'VulnPatchPairs-Train.json'))
vpp_valid = pd.read_json(os.path.join(base_dir, 'VulnPatchPairs-Valid.json'))
vpp_test  = pd.read_json(os.path.join(base_dir, 'VulnPatchPairs-Test.json'))

# 分离漏洞和补丁函数
vpp_train = separate_vulns_and_patches(vpp_train)
vpp_valid = separate_vulns_and_patches(vpp_valid)
vpp_test  = separate_vulns_and_patches(vpp_test)

# 保存 CSV
vpp_train.to_csv(os.path.join(output_dir, 'vpp_train.csv'), index=False)
vpp_valid.to_csv(os.path.join(output_dir, 'vpp_valid.csv'), index=False)
vpp_test.to_csv(os.path.join(output_dir, 'vpp_test.csv'), index=False)

# 保存 JSON（每行一个记录）
vpp_train.to_json(os.path.join(output_dir, 'vpp_train.json'), orient='records', lines=True)
vpp_valid.to_json(os.path.join(output_dir, 'vpp_valid.json'), orient='records', lines=True)
vpp_test.to_json(os.path.join(output_dir, 'vpp_test.json'), orient='records', lines=True)

# 打印样本统计
print(f"Train samples: {len(vpp_train)} (Vulns: {sum(vpp_train.target==1)}, Patches: {sum(vpp_train.target==0)})")
print(f"Valid samples: {len(vpp_valid)} (Vulns: {sum(vpp_valid.target==1)}, Patches: {sum(vpp_valid.target==0)})")
print(f"Test samples:  {len(vpp_test)}  (Vulns: {sum(vpp_test.target==1)}, Patches: {sum(vpp_test.target==0)})")

print(f"\nAll CSV and JSON files are saved in: {output_dir}")
