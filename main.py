#scanning library
from bluepy.btle import Scanner, DefaultDelegate

# pexpect API
from pexpect import *

# Standard API
import os, threading
from datetime import datetime
import time, sys

# Save Advertise Data
# Global Variable
#global ad_data
#allLength, LogicalDst, LogicalSrc, PhysicalDst, PhysicalSrc, IsUrgent, urgentLevel
ad_data = "09 08 FF 06 02 01 03 01 01 01"
#nodes -> addr1, addr2, addr3
# addrs = ["b8:27:eb:b8:f2:02", "b8:27:eb:5b:fc:b2", "b8:27:eb:9c:e4:26"]
#A node1
addrs = ["b8:27:eb:5b:fc:b2"]
#B node2
addrs = ["b8:27:eb:b8:f2:02", "b8:27:eb:9c:e4:26"]
#C node3
addrs = ["b8:27:eb:5b:fc:b2"]

myAddr = sys.argv[1]
print("addr: " + myAddr)

class ScanDelegate(DefaultDelegate):
    def __init__(self):
        DefaultDelegate.__init__(self)

# Reset hci0
def reset_hci():
    os.system("sudo hciconfig hci0 down")
    os.system("sudo hciconfig hci0 up")

# Set Interval
def set_advertise_interval():
    #interval = input("Advertise Interval(sec) is ")
    # HCI_LE_Set_Advertising_Parameters
    run("sudo hcitool -i hci0 cmd 0x08 0x0006 40 06 40 06 03 00 00 00 00 00 00 00 00 07 00")

# Set Advertise Data
def set_advertise_data():
    # https://stackoverflow.com/questions/44404093/timeout-for-10-seconds-while-loop-in-python
    # start time
    start_time = datetime.now()
    while True:
        # if time is 10 seconds after start time then loop exit
        time_delta = datetime.now() - start_time
        if time_delta.total_seconds() >= 10:
            break

        # Global Variable
        global ad_data
        # HCI_LE_Set_Advertising_Data
        run("sudo hcitool -i hci0 cmd 0x08 0x0008 " + str(ad_data))


# Enable Advertise Mode
def advertise_enable():
    # HCI_LE_Set_Advertise_Enable
    run("sudo hcitool -i hci0 cmd 0x08 0x000A 01")
    print("Successful!!!")

def Advertising():
    print("Advertise")
    reset_hci()
    set_advertise_interval()
    advertise_enable()
    set_advertise_data()

    # Thread
    scanning_thread = threading.Thread(target=Scanning)
    # Thread start
    scanning_thread.start()

def Scanning():
    print("Scan")
    reset_hci()

    scanner = Scanner().withDelegate(ScanDelegate())

    # 10 seconds
    count = 0
    time = 10
    while count < time:
        devices = scanner.scan(1.0) # arg is ................

        # print("\nstart scan...")

        for dev in devices:
            if dev.addr in addrs:  # if cur address is in addrs
                print("recv packet's address : %s" % dev.addr)
                for (adtype, desc, value) in dev.getScanData():
                    # print ManufacturerSpecificData
                    #print(split_data(value)[0])
                    print("values : %s" % value)
                    recv_data = split_data(value)
                    # check recv_dats is right data or not
                    # if check_data(recv_data) is true, it means recv_data is not mine
                    # so we make new packet
                    if check_data(recv_data):
                        global ad_data
                        ad_data = make_new_data(recv_data)
                        print("new data : %s" % ad_data)

        count = count + 1

    # Thread
    advertising_thread = threading.Thread(target=Advertising())
    # Thread start
    advertising_thread.start()

def split_data(data):
    # dividing data by two digits
    return [data[i:i+2] for i in range(0, len(data), 2)]

def check_data(recv_data):
    all_length = len(recv_data)
    length = recv_data[0]

    if all_length >= 7: # whole recv_data must be 7 or more
        print("all length good!")

        if int(length) >= 6:  # if length is more than 6, check logical destination
            print("length good!")

            l_dst = recv_data[1]
            if l_dst == myAddr:  # if l_dst == myaddr, check physical dst
                print("l_dst good!")

                p_dst = recv_data[3]
                if p_dst == myAddr:  # if p_dst = myaddr, transfer complete
                    print("this data is mine!")
                    print(recv_data)
                    return True
                else:  # if p_dst != myaddr, make new packet and send it
                    return True

            else:
                return False
        else:
            return False
    else:
        return False


def make_new_data(recv_data):
    new_data = recv_data[:]

    #change logical src
    new_data[2] = myAddr.encode("utf-8").decode("utf-8")
    #check routing table and find next logical dst
    new_data[1] = check_routingtable(recv_data[2]).encode("utf-8").decode("utf-8")

    #check isUrgent is true or not
    #if isUrgent is true, urgentLevel + 1
    #if isUrgent is false, no increase
    if recv_data[5]:
        new_data[6] = "0" + str((int(recv_data[6]) + 1)).encode("utf-8").decode("utf-8") #convert to string
        print("new urgent level : %s" % new_data[6])


    new_data = "09 08 FF " + ' '.join(new_data)

    return new_data

def check_routingtable(l_src):
    if myAddr == "01":
        routingtable = ["02"]
    elif myAddr == "02":
        routingtable = ["01", "03"]  #in close order
    elif myAddr == "03":
        routingtable = ["02", "01"]

    next_dst_index = routingtable.index(l_src) + 1

    return routingtable[next_dst_index]

def Main():

    if myAddr == "01":
        Advertising()
    elif myAddr == "02":
        Scanning()
    elif myAddr == "03":
        Advertising()

Main()







