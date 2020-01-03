#!/usr/local/bin/python3
#how to run
#sudo su
#sudo pip3 install pyshark
#python3 logFlows

import pyshark
import datetime as dt
import threading


cap = pyshark.LiveCapture(interface='en0', bpf_filter='ip and tcp')

cap.sniff(packet_count=100)


class info:
    packet_sent_number = 0
    bytes_sent = 0
    packet_received_number = 0
    bytes_received = 0
    src_ip = ""
    dst_ip = ""
    src_port = ""
    dst_port = ""
    protocal = ""
    def __init__(self,src_ip, src_port, dst_ip, dst_port, protocol):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port =src_port
        self.dst_port =dst_port
        self.protocal = protocol

info_in_one_second = {}

def print_conversation_header(pkt):
    global info_in_one_second
    try:
        dst_addr = pkt.ip.dst
        dst_port = pkt[pkt.transport_layer].dstport
        src_addr = pkt.ip.src
        src_port = pkt[pkt.transport_layer].srcport
        protocal =  pkt.transport_layer
        #print(dst_addr+dst_port+src_addr+src_port+protocal)
        myinfo = info_in_one_second.get(src_addr + '_' + src_port + "_" + dst_addr + "_" + dst_port + protocal, info(src_addr, src_port, dst_addr, dst_port, protocal))
        myinfo.packet_sent_number = myinfo.packet_sent_number + 1
        myinfo.bytes_sent = myinfo.bytes_sent + int(pkt.length)
        anotherinfo = info_in_one_second.get(dst_addr + '_' + dst_port + "_" + src_addr + "_" + src_port + protocal,
                                             info(dst_addr, dst_port, src_addr, src_port, protocal))
        anotherinfo.packet_received_number = anotherinfo.packet_received_number + 1
        anotherinfo.bytes_received = anotherinfo.bytes_received + int(pkt.length)

        info_in_one_second[src_addr + '_' + src_port + "_" + dst_addr + "_" + dst_port + protocal]=myinfo
        info_in_one_second[dst_addr + '_' + dst_port + "_" + src_addr + "_" + src_port + protocal]=anotherinfo
    except AttributeError as e:
        #ignore packets that aren't TCP/UDP or IPv4
        print(e)
        pass
    except Exception as e:
        print(e)

#timer
def printPerSecond():
    global info_in_one_second
    #print..
    time = dt.datetime.now()
    data = info_in_one_second
    print("In one second........\ntime\tsrc_ip\tsrc_port\tdst_ip\tdst_port\tproto\t#pkt_sent\t#pkt_rec\t#bytes_sent\t#bytes_rec")
    for myinfo in data:
        print ('%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' % (time, data[myinfo].src_ip, data[myinfo].src_port, data[myinfo].dst_ip,data[myinfo].dst_port, data[myinfo].protocal, data[myinfo].packet_sent_number,  data[myinfo].packet_received_number, data[myinfo].bytes_sent, data[myinfo].bytes_received))
    #clear
    info_in_one_second = {}
    #sleep and then do it again
    threading.Timer(1, printPerSecond).start()

printPerSecond()

cap.apply_on_packets(print_conversation_header, timeout=100)


