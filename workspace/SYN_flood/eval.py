
import matplotlib.pyplot as plt
import numpy as np

# flood command run on kali ZH:
# sudo hping3 -I eth1 -c 15000 -d 12 -S -w 64 -p 30252 --flood --rand-source 192.168.111.1 

flood_file_local = 'scion_ping_flood_local.txt'
normal_file_local = 'scion_ping_normal_local.txt'
flood_file_extern = 'scion_ping_flood_extern.txt'
normal_file_extern = 'scion_ping_normal_extern.txt'

flood_data_local = []
normal_data_local = []
flood_data_extern = []
normal_data_extern = []

def get_data(file_name, data):
    with open(file_name, 'r') as f:
        for line in f:
            if "time=" in line:
                time = line.split('time=')[1].split('ms')[0]
                data.append(float(time))
            if "packet loss" in line:
                loss = line.split('%')[0].split(' ')[-1]
    return int(loss)
loss_flood_local = get_data(flood_file_local, flood_data_local)
loss_normal_local = get_data(normal_file_local, normal_data_local)
loss_flood_extern = get_data(flood_file_extern, flood_data_extern)
loss_normal_extern = get_data(normal_file_extern, normal_data_extern)

flood_data_local = np.array(flood_data_local)
normal_data_local = np.array(normal_data_local)
flood_data_extern = np.array(flood_data_extern)
normal_data_extern = np.array(normal_data_extern)

# plot mean and std
# 2 groups: local and external
fig, ax = plt.subplots(layout='constrained')
bar_width = 0.35
bar1 = np.mean(flood_data_local)
bar2 = np.mean(normal_data_local)
bar3 = np.mean(flood_data_extern)
bar4 = np.mean(normal_data_extern)
std1 = np.std(flood_data_local)
std2 = np.std(normal_data_local)
std3 = np.std(flood_data_extern)
std4 = np.std(normal_data_extern)

x_pos = np.arange(2)

ax.bar(x_pos, [bar2, bar4], bar_width, yerr=[std2, std4], align='center', alpha=0.5, ecolor='black', capsize=10, label='Normal')
ax.bar(x_pos + bar_width, [bar1, bar3], bar_width, yerr=[std1, std3], align='center', alpha=0.5, ecolor='black', capsize=10, label='SYN Flood')
ax.set_xticks(x_pos + bar_width / 2, ['Local', 'Extern'])

# write loss into bars
ax.text(x_pos[0], 0, f'Loss: {loss_normal_local}%', ha='center', va='bottom')
ax.text(x_pos[1], 0, f'Loss: {loss_normal_extern}%', ha='center', va='bottom')
ax.text(x_pos[0] + bar_width, 0, f'Loss: {loss_flood_local}%', ha='center', va='bottom')
ax.text(x_pos[1] + bar_width, 0, f'Loss: {loss_flood_extern}%', ha='center', va='bottom')

plt.xticks(rotation=0)
plt.grid()
plt.legend()


#y axis label (ms)
plt.ylabel('Time [ms]')
plt.title('SCION Ping duration comparison')
plt.savefig("ping_duration.png")
