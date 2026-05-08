import matplotlib.pyplot as plt

# Data
K = [1, 2, 3, 5, 10]
cve_vulnerability_time = [0.07, 0.06, 0.06, 0.13, 0.13]
cve_patch_time = [0.06, 0.06, 0.06, 0.12, 0.19]
ipid_vulnerability_time = [73.69, 60.74, 96.61, 170.08, 357.10]
ipid_patch_time = [0.13, 0.12, 0.22, 0.13, 0.19]

plt.figure(figsize=(8, 5))

# Vulnerabilities (red)
plt.plot(K, cve_vulnerability_time, marker='o', color='red', linewidth=2, alpha=0.8, label='cve_2016_5696_vulnerability')
plt.plot(K, ipid_vulnerability_time, marker='s', color='red', linestyle='--', linewidth=2, alpha=0.8,
         label='ipid_downgrade_vulnerability')

# Patches (green)
plt.plot(K, cve_patch_time, marker='o', color='green', linewidth=2, alpha=0.8, label='cve_2016_5696_patch')
plt.plot(K, ipid_patch_time, marker='s', color='green', linestyle='--', linewidth=2, alpha=0.8,
         label='ipid_downgrade_patch')

# Annotations
for x, y in zip(K, ipid_vulnerability_time):
    plt.text(x, y * 1.2, f"{y:.2f} s", fontsize=8, ha='center')
for x, y in zip(K, ipid_patch_time):
    plt.text(x, y * 1.2, f"{y:.2f} s", fontsize=8, ha='center')

plt.xlabel('K value')
plt.ylabel('Time (seconds, log scale)')
plt.title('Execution Time vs K')
plt.yscale('log')
plt.legend()
plt.grid(True)

plt.savefig("Execution Time vs K.png", dpi=300, bbox_inches='tight')
plt.show()