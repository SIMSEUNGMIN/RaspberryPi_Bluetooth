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
ad_data = "07 06 FF  04 01 01 01 01"
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
                        ad_data = make_new_packet(recv_data)
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
    neighbor = check_myNeighborTable(myAddr)  # Get my neighbor table
    all_data_len = len(recv_data)  # All Data Length (include Data Length byte)
    pure_data_len = recv_data[0]  # pure Data Length (except Data Length byte)

    if all_data_len == 5:  # whole recv_data_length must be 5 (is always 5)
        print("all data length good!")

        if int(pure_data_len) == 4:  # pure_data_length is the length except Data Length byte, so it must be 4
            print("pure data length good!")

            l_src = recv_data[2]
            if l_src == myAddr:  # if l_src == myAddr, this data throws away because this is data I sent
                return False
            else:  # this is not data I sent
                print("this packet is not packet I sent")

                p_src = recv_data[1]
                if is_neighbor(p_src, neighbor):  # if p_src is my neighbor, check l_src again
                    print("p_src is my neighbor")
                    if is_neighbor(l_src, neighbor):  # if both p_src and l_src are my neighbor, check p_src and l_src are the same
                        print("both p_src and l_src are my neighbor")
                        if p_src == l_src:  # if p_src and l_src are the same, this is the data I can receive
                            print("p_src and l_src are the same")
                            return True
                        else:  # not the same, this is duplicated data. So throw away
                            return False
                    else:  # if p_src is my neighbor and l_src is not my neighbor, this is the data I can receive
                        print("p_src is my neighbor and l_src is not my neighbor")
                        return True

                else:  # this data is not from my neighbor
                    return False
        else:
            return False
    else:
        return False


def make_new_packet(recv_data):
    new_data = recv_data[:]  # copy data to make new data

    # only change physical src, need not change logical src
    new_data[1] = myAddr.encode("utf-8").decode("utf-8")

    # check isUrgent is true or not
    # if isUrgent is true, urgentLevel + 1
    # if isUrgent is false, no increase
    if recv_data[3]:  # recv_data[3] is isUrgent byte
        new_level = (int(recv_data[4]) + 1)
        if new_level >= 10:  # if new_level is more than 10, do not need attach "0"
            new_data[4] = str(new_level).encode("utf-8").decode("utf-8")
        else: # if new_level is not more than 10, must attach "0"
            new_data[4] = "0" + str((int(recv_data[4]) + 1)).encode("utf-8").decode("utf-8")  # convert to string

        print("new urgent level : %s" % new_data[4])


    new_packet = "07 06 FF " + ' '.join(new_data)

    return new_packet


def is_neighbor(src, neighbor):
    if src in neighbor:
        return True
    else:
        return False


def check_myNeighborTable(addr):
    if addr == "01":
        neighborTable = ["02"]
    elif addr == "02":
        neighborTable = ["01", "03"]
    elif addr == "03":
        neighborTable = ["02"]

    return neighborTable


def Main():

    if myAddr == "01":
        Advertising()
    elif myAddr == "02":
        Scanning()
    elif myAddr == "03":
        Advertising()

Main()







