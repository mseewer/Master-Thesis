import os
import re
import numpy as np
import matplotlib.pyplot as plt

data_folder = 'data'
log_files = [f for f in os.listdir(data_folder) if f.startswith('internet2_') and f.endswith('.log')]

traffic_amounts = []
avg_ping_times = []
std_ping_times = []
loss_rates = []
achieved_bandwidths = []

for log_file in log_files:
    file_path = os.path.join(data_folder, log_file)
    with open(file_path, 'r') as file:
        content = file.read()
        
        # Extract the traffic amount from the filename
        traffic_amount = int(re.search(r'internet2_(\d+)g', log_file).group(1))
        traffic_amounts.append(traffic_amount)
        
        # Extract average ping time and standard deviation
        rtt_match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/([\d.]+) ms', content)
        if rtt_match:
            avg_ping_time = float(rtt_match.group(1))
            std_ping_time = float(rtt_match.group(2))
        else:
            avg_ping_time = 0
            std_ping_time = 0
        
        avg_ping_times.append(avg_ping_time)
        std_ping_times.append(std_ping_time)
        
        # Extract loss rate
        loss_rate_match = re.search(r'(\d+)% packet loss', content)
        if loss_rate_match:
            loss_rate = float(loss_rate_match.group(1))
        else:
            loss_rate = 0
        
        loss_rates.append(loss_rate)
        
        # Extract achieved bandwidth (C->S)
        bandwidth_match = re.search(r'C->S results.*?Achieved bandwidth: [\d]+ bps / ([\d.]+) Mbps', content, re.DOTALL)
        if bandwidth_match:
            achieved_bandwidth = float(bandwidth_match.group(1))
        else:
            achieved_bandwidth = 0
        
        achieved_bandwidths.append(achieved_bandwidth)

# Sort data by traffic amount
sorted_indices = np.argsort(traffic_amounts)
traffic_amounts = np.array(traffic_amounts)[sorted_indices]
avg_ping_times = np.array(avg_ping_times)[sorted_indices]
std_ping_times = np.array(std_ping_times)[sorted_indices]
loss_rates = np.array(loss_rates)[sorted_indices]
achieved_bandwidths = np.array(achieved_bandwidths)[sorted_indices]
labels = [f'{ta}' for ta in traffic_amounts]

# Plotting
fig, ax1 = plt.subplots(figsize=(12, 8))

color = 'tab:blue'
ax1.set_xlabel('Traffic Amount [Gb/s]')
ax1.set_ylabel('Average Ping Time [ms]', color=color)
shift = 1
ax1.bar(labels, avg_ping_times+shift, yerr=std_ping_times, color=color, alpha=0.6, label='Avg Ping Time', bottom=-shift, capsize=5)
ax1.tick_params(axis='y', labelcolor=color)
ax1.set_ylim(-shift, 26.5)

ax2 = ax1.twinx()
color = 'tab:red'
ax2.set_ylabel('Ping Loss Rate (%)', color=color)
ax2.plot(labels, loss_rates, color=color, marker='o', linestyle='-', label='Ping Loss Rate')
ax2.tick_params(axis='y', labelcolor=color)
ax2.set_ylim(-5, 105)


ax3 = ax1.twinx()
color = 'darkgreen'
ax3.spines['right'].set_position(('outward', 60))
ax3.set_ylabel('Achieved Bandwidth [Mb/s]', color=color)
ax3.plot(labels, achieved_bandwidths, color=color, marker='x', linestyle='--', label='Achieved Bandwidth')
ax3.tick_params(axis='y', labelcolor=color)
ax3.set_ylim(-35, 735)

fig.tight_layout()
plt.savefig('internet_analysis_notitle.png')

plt.title('Impact of Volumetric Internet Traffic', fontsize=16)
fig.tight_layout()
# plt.show()
plt.savefig('internet_analysis.png')