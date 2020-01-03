# Phase3
# author Ying Zhang & Yujia Qiu
import pyshark
from sklearn.externals import joblib
import pickle
import statistics as stats
from scipy.stats import skew
from scipy.stats import kurtosis
import sys
import os

target_names = ['Unknown', 'Browser', 'Fruit', 'News', 'Weather', 'Youtube']

print("#"*100)
pcap_name = sys.argv[1]
print(pcap_name)
pred_flag = sys.argv[2]
# print(pred_flag)

if pred_flag == 'True':
    model = joblib.load('model.pkl')

cap = pyshark.FileCapture(pcap_name, only_summaries=True)
packet_list = []
def get_packet_list(pkt):
    try:
        if pkt.protocol == 'TCP' or pkt.protocol == 'UDP':
            src_port = pkt.info.split(' ')[0]
            tgt_port = pkt.info.split(' ')[2]
            packet_list.append([pkt.no, float(pkt.time), pkt.source, pkt.destination, float(pkt.length), pkt.protocol, src_port, tgt_port])
    except AttributeError as e:
        print("Error",e)
        pass
cap.apply_on_packets(get_packet_list)


### traffic flows in both directions
def combine_src_tgt(src,tgt,src_port, tgt_port,protocol):
    if src > tgt:
        index = (src,src_port,tgt,tgt_port,protocol)
        direction = 'send'
    else:
        index = (tgt,tgt_port,src,src_port,protocol)
        direction = 'receive'
    return index,direction

def generate_feature_vector(key,value):
    src, tgt, src_port, tgt_port, protocol = key[0],key[1],key[2],key[3],key[4]
    packet_lengths = value['packet_lengths']
    time_list = value['time_list']
    bytes_send = value['bytes_send']
    packets_send = value['packets_send']
    bytes_receive = value['bytes_receive']
    packets_receive = value['packets_receive']

    protocol_type = 1 if protocol == 'TCP' else 0
    byte_ratio = bytes_send / float(bytes_receive) if bytes_send < bytes_receive else bytes_receive / float(bytes_send)
    packet_ratio = packets_send / float(packets_receive) if packets_send < packets_receive else packets_receive / float(packets_send)
    packets_length_mean = stats.mean(packet_lengths)
    packets_length_min = min(packet_lengths)
    packets_length_max = max(packet_lengths)
    packets_length_std = stats.stdev(packet_lengths) if len(packet_lengths) > 2 else 0.0
    packet_lengths_kurtosis = kurtosis(packet_lengths) if len(packet_lengths) > 2 else 0
    packet_lengths_skew = skew(packet_lengths) if len(packet_lengths) > 2 else 0


    time_list.sort()
    time_diff_list = []
    i = 0
    while i < len(time_list) - 1:
        time_diff_list.append(time_list[i + 1] - time_list[i])
        i += 1

    time_diff_mean = stats.mean(time_diff_list) if len(time_diff_list) > 0 else 0
    time_diff_min = min(time_diff_list) if len(time_diff_list) > 0 else 0
    time_diff_max = max(time_diff_list) if len(time_diff_list) > 0 else 0
    time_diff_std = stats.stdev(time_diff_list) if len(time_diff_list) > 2 else 0
    time_diff_kurtosis = kurtosis(time_diff_list) if len(time_diff_list) > 2 else 0
    time_diff_skew = skew(time_diff_list) if len(time_diff_list) > 2 else 0

    feature = [protocol_type, byte_ratio, packet_ratio,
          packets_length_mean, packets_length_min, packets_length_max,packets_length_std,packet_lengths_kurtosis,packet_lengths_skew,
          time_diff_mean, time_diff_min, time_diff_max, time_diff_std, time_diff_kurtosis, time_diff_skew]

    return feature

# print("Len of packet_list； ",len(packet_list))

feature_vector_list = []
flow_dict = {}
burst_num = 0
"""
Burst 1:
<timestamp> <src addr> <dst addr> <src port> <dst port> <proto> <#packets sent> <#packets rcvd> <#bytes send> <#bytes rcvd> <label>
"""

for idx, packet in enumerate(packet_list):
    # print(packet)
    if idx == 0:
        pre_time = packet[1]
    else:
        cur_time = packet[1]
        if (len(flow_dict) > 0 and cur_time - pre_time >= 1) or idx == len(packet_list) - 1:
            burst_num += 1
            print("Burst %d:" % burst_num)

            for key, value in flow_dict.items():
                feature = generate_feature_vector(key, value)
                feature_vector_list.append(feature)

                if pred_flag == 'True':
                    src, tgt, src_port, tgt_port, protocol = key[0], key[1], key[2], key[3], key[4]
                    bytes_send = value['bytes_send']
                    packets_send = value['packets_send']
                    bytes_receive = value['bytes_receive']
                    packets_receive = value['packets_receive']
                    cur_time = value["cur_time"]

                    prediction = model.predict([feature])
                    pred = prediction[0]
                    prob = model.predict_proba([feature])
                    prob[0].sort()
                    pred_first = prob[0][-1]
                    pred_second = prob[0][-2]
                    if pred_first - pred_second < .2 or pred_first < .3:
                        pred = 0
                    label_name = target_names[pred]
                    log_str = "<%s> <%s> <%s> <%s> <%s> <%s> <%s> <%s> <%s> <%s> <%s>" \
                              %(cur_time,src,tgt,src_port,tgt_port,protocol,str(packets_send),str(packets_receive),str(bytes_send),str(bytes_receive),label_name)
                    print(log_str)
            flow_dict = {}
        else:
            # print(idx)
            src = packet[2]
            tgt = packet[3]
            length = packet[4]
            protocol = packet[5]
            src_port = packet[6]
            tgt_port = packet[7]
            index,direction = combine_src_tgt(src, tgt, src_port, tgt_port, protocol)
            if index not in flow_dict:
                flow_dict[index] = {
                    'cur_time': cur_time,
                    'packet_lengths': [length],
                    'time_list': [cur_time]
                }
                if direction == 'send':
                    flow_dict[index]['bytes_send'] = length
                    flow_dict[index]['packets_send'] = 1
                    flow_dict[index]['bytes_receive'] = 0
                    flow_dict[index]['packets_receive'] = 0
                else:
                    flow_dict[index]['bytes_receive'] = length
                    flow_dict[index]['packets_receive'] = 1
                    flow_dict[index]['bytes_send'] = 0
                    flow_dict[index]['packets_send'] = 0
            else:
                flow_dict[index]['cur_time'] = cur_time
                flow_dict[index]['packet_lengths'].append(length)
                flow_dict[index]['time_list'].append(cur_time)
                if direction == 'send':
                    flow_dict[index]['bytes_send'] += length
                    flow_dict[index]['packets_send'] += 1
                else:
                    flow_dict[index]['bytes_receive'] += length
                    flow_dict[index]['packets_receive'] += 1
        pre_time = cur_time  ## update time


if pred_flag == 'False':
    label_name = pcap_name.split('/')[-2]
    file_name = os.path.join('feature/', label_name, pcap_name.split("/")[-1].split('.')[0] + ".feature")
    pickle.dump(feature_vector_list, open(file_name, "wb"))
    # print(feature_vector_list)
print("#"*100)
