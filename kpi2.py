import pyshark
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt

speed_of_light = 300000000
cqi = { 1:(15, 0.9258),
        2:(15, 0.9258),
        3:(15, 0.9258),
        4:(14, 0.8525),
        5:(14, 0.8525),
        6:(13, 0.7539),
        7:(12, 0.6504),
        8:(12, 0.6504),
        9:(12, 0.6504),
        10:(11, 0.5537),
        11:(10, 0.4551),
        12:(9, 0.6016),
        13:(9, 0.6016),
        14:(8, 0.4785),
        15:(7, 0.3691),
        16:(6, 0.5879),
        17:(5, 0.4385),
        18:(4, 0.3008),
        19:(3, 0.1885),
        20:(2, 0.1172),
        21:(1, 0.0762)
        }


timestamp_at_mouth = []
timestamp_at_ear = []
initial_list = []
final_list = []


def GenericFilter(name_file, filter):
	print("TLS filter : ", filter)
	capture = pyshark.FileCapture(name_file, display_filter=filter)
	#print(len(capture)) #Check why length is not working
	packet_and_timestamp = []
	for packet in capture:
		packet_and_timestamp.append([packet.number, float(packet.frame_info.time_epoch)])
	return(packet_and_timestamp)


file_name = input("Enter the file name to consider for kpi 2 : ")
current_path = Path.cwd()
file_name = str(current_path) + "/" + file_name
print(f" Path to pcap file : {file_name}")

mouth_filter = "ip.src == 12.1.1.2 and ip.dst == 169.55.65.207 and tcp and frame.len == 426"
ear_filter = "ip.src == 169.45.211.199 and ip.dst == 12.1.1.3 and tcp and frame.len == 426"

timestamp_at_mouth = GenericFilter(file_name, mouth_filter)
print(f" Packet number and timestamp for mouth latency : {timestamp_at_mouth}")
timestamp_at_ear = GenericFilter(file_name, ear_filter)
print(f" Packet number and timestamp for ear latency : {timestamp_at_ear}")

total_mouth_packets = len(timestamp_at_mouth)
total_ear_packets = len(timestamp_at_ear)
print(f"Mouth packets : {total_mouth_packets} and Ear packets : {total_ear_packets}")

for i in range(total_mouth_packets):
    if i == total_mouth_packets-1:
        for k in range(total_ear_packets):
            if int(timestamp_at_mouth[i][0])<int(timestamp_at_ear[k][0]):
                initial_list.append((float(timestamp_at_mouth[i][1]), float(timestamp_at_ear[k][1])))
                break
            else:
                continue
    else:
        for j in range(total_ear_packets):
            if int(timestamp_at_mouth[i][0])<int(timestamp_at_ear[j][0])<int(timestamp_at_mouth[i+1][0]):
                initial_list.append((float(timestamp_at_mouth[i][1]), float(timestamp_at_ear[j][1])))
                break
            else:
                continue
print(initial_list)

M2E_latency = []
for h in initial_list:
    M2E_latency.append((h[1]-h[0])*1000)

print(f"Wireshark M2E latency values : {M2E_latency}")


phone = int(input("""Transmitter Phone
            1. Xiaomi 
            2. Google 
Enter your input in number : """))
if phone == 1 or phone == 2:
    if(phone == 1):
        tcp_packet = 232
    elif(phone == 2):
        tcp_packet = 356
    tcp_header = 20    
    hop= float(input("number of hops : "))
    distance = int(input("Enter phone distance between 1 to 21 : "))
    if distance in cqi.keys():
        Dprop = distance/speed_of_light
        packet_size = (tcp_packet+tcp_header)*8
        modem_rate = cqi[distance][1] * 1024
        Dtrans = packet_size/modem_rate
        M2E = (hop+1)*Dprop + hop*Dtrans
        print(" Mouth to Ear Latency is : ", M2E)
    else:
        print("The distance is not present in the CQI table")
else:
    print("The number is Invalid")


for x in M2E_latency:
    final_value = float(x)+float(M2E)
    final_list.append(final_value)

print(f"Wireshark M2E latency values : {M2E_latency}")
print(" Mouth to Ear Latency is : ", M2E)
print(f"Final Latency values after adding therotical latency : {final_list}")


kpi2_value = 300
count = 0
for value in final_list:
    if value < kpi2_value:
        count +=1
total_samples = (count/len(final_list)) * 100


x = np.sort(final_list)
#x = np.sort(number_of_samples)
print(f"sorted_data M2E Latency : {x}")

# For M2E theoritical latency
plt.xlim(0,21)
#plt.xticks(range(0,22,2))
plt.scatter(distance, M2E, marker ="o")
plt.show()

#For Final M2E latency
y = (np.arange(len(x)) / float(len(x)-1))*100
plt.xlabel('Mouth to Ear Latency in milli Seconds')
plt.ylabel('CDF in %')
plt.title(f'KPI 2 - {total_samples} % values lies within 300ms')
plt.plot(x, y, marker='o')
plt.show()









