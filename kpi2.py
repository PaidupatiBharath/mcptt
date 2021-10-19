import pyshark
from pathlib import Path
import numpy as np
import matplotlib.pyplot as plt

speed_of_light = 300000000
cqi = { 0:2768,
        1:4432,
        2:7248,
        3:10320,
        4:12400,
        5:13936,
        6:15984,
        7:31968,
        8:39648,
        9:51840,
        10:61056,
        11:98496,
        12:119088,
        13:137520,
        14:164256,
        15:183456
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
        packet_size = 426
    elif(phone == 2):
        packet_size = 426
    hop= int(input("number of hops : "))
    downlink_range = int(input("Enter downlink range distance : "))
    cqi_value = int(input("Enter the CQI value from 0 to 15 : "))
    uplink_range = downlink_range
    Rmax = ((2*uplink_range)+((hop-1)*(downlink_range)))
    if cqi_value in cqi.keys():
        Dprop = Rmax/speed_of_light
        modem_rate = cqi[cqi_value]
        Dtrans = packet_size/modem_rate
        M2E = ((hop+1)*Dprop + hop*Dtrans)*1000
        print(" Mouth to Ear Latency is : ", M2E)
        print("Applied wideband codec rate :", cqi[cqi_value])
    else:
        print("The distance is not present in the table")
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
experimental_val = []
for value in final_list:
    if value < kpi2_value:
        count +=1
        experimental_val.append(value)
if count != 0:
    total_samples = (count/len(final_list)) * 100
    experimental_samples = (count/len(experimental_val)) * 100
else:
    print("""
    All values are greater than defined KPI values
    so stopping the program
    """)
    exit()



x = np.sort(final_list)
z = np.sort(experimental_val)
#x = np.sort(number_of_samples)
print(f"sorted_data M2E Latency : {x}")

# For M2E theoritical latency
plt.xlim(0,Rmax)
#plt.xticks(range(0,22,2))
plt.scatter(Rmax, M2E, marker ="o")
plt.show()

#For Final M2E latency
y = (np.arange(len(x)) / float(len(x)-1))*100
plt.xlabel('Mouth to Ear Latency in milli Seconds')
plt.ylabel('CDF in %')
plt.title(f'KPI 2 - {total_samples} % values lies within 300ms')
plt.plot(x, y, marker='o')
plt.show()


#Experimental M2E for personal
y = (np.arange(len(z)) / float(len(z)-1))*100
plt.xlabel('Mouth to Ear Latency in milli Seconds')
plt.ylabel('CDF in %')
plt.title(f'KPI 2 - {experimental_samples} % values lies within 300ms')
plt.plot(z, y, marker='o')
plt.show()










