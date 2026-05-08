import matplotlib.pyplot as plt

# Data
K = [1, 2, 3, 5, 10]
cve_vulnerability_memory = [0.73, 0.14, 0.09, 9.78, 10.77]
cve_patch_memory  = [0.72, 0.66, 0.66, 14.08, 23.16]
ipid_vulnerability_memory = [420.81, 756.39, 1017.84, 1465.44, 2822.75]
ipid_patch_memory  = [10.20, 9.66, 34.69, 24.73, 34.33]

plt.figure(figsize=(8, 5))

# Vulnerabilities (red)
plt.plot(K, cve_vulnerability_memory , marker='o', color='red', linewidth=2, alpha=0.8, label='cve_2016_5696_vulnerability')
plt.plot(K, ipid_vulnerability_memory , marker='s', color='red', linestyle='--', linewidth=2, alpha=0.8,
         label='ipid_downgrade_vulnerability')

# Patches (green)
plt.plot(K, cve_patch_memory , marker='o', color='green', linewidth=2, alpha=0.8, label='cve_2016_5696_patch')
plt.plot(K, ipid_patch_memory , marker='s', color='green', linestyle='--', linewidth=2, alpha=0.8,
         label='ipid_downgrade_patch')

# Annotations
for x, y in zip(K, ipid_vulnerability_memory):
    plt.text(x, y * 1.2, f"{y:.0f} MB", fontsize=6, ha='center')
for x, y in zip(K, ipid_patch_memory):
    plt.text(x, y * 1.3, f"{y:.0f} MB", fontsize=6, ha='center')

plt.xlabel('K value')
plt.ylabel('Memory (MB, log scale)')
plt.title('Memory Usage vs K')
plt.yscale('log')
plt.legend()
plt.grid(True)

plt.savefig("Memory Usage vs K.png", dpi=300, bbox_inches='tight')
plt.show()