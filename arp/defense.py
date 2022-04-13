"""
References:
https://scapy.readthedocs.io/en/latest/
https://www.geeksforgeeks.org/network-scanning-using-scapy-module-python/?ref=rp

EECE 655 Assignment 2 - Fall 20-21
October 23, 2020
This code implements a detector for an ARP cache poisoning attack.

--------------------Two Defense Strategies-------------------------

               -----------Strategy 1-----------
Get ARP table of all hosts and check for duplicate MAC addresses.
If duplicates exits, then one or more MAC addresses are spoofed.

              ------------Strategy 2-----------
Sniff the network for ARP replies.
Upon reading a reply, the detector reads the source MAC address.
Let's call it MAC_address_suspicious.
The detector then sends an arp request to the sender.
The sender replies back with its MAC address.
Let's call it MAC_address_sender.
If MAC_address suspicious and MAC_address_sender are equal, 
then no attack is detected.
Else, MAC_address_suspicious is spoofed. Attack is detected
-------------------------------------------------------------------

Developed by: Aline Challita & Edmond Samaha
NOTE: The author of each function is indicated before the start of each function.
"""

import os, platform, subprocess, threading
from datetime import datetime
from scapy.all import *

"""
NOTE: Some Scapy specific funtions may show up as errors/undefined in editors
but actually they are not errors just subprocesses that run on command line
"""

numarp=0 #number of arp packets detected on network

#region FUNCTIONS

"""
Authors: Aline for oneMac=False; Edmond for oneMac=True
Function is tested
"""
def getMacs(ip, oneMac=True):
    """
    --------------Function Description--------------- 
    Scans the LAN network for available hosts:
    *create an ARP request for target IP address
    *create a broadcast ethernet frame
    *put arp request inside the ethernet frame
    *send the arp request frame
    *receive response
    *parse IP and MAC addresses from response
    *print ARP table of available hosts on the network
    -------------------------------------------------
    """
    arp = ARP(pdst=ip)                      #create an ARP packet where pdst is dest IP 
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  #create ethernet frame with broadcast dest MAC address
    arp_broadcast_packet = ether/arp        #append arp packet inside ethernet frame

    #Now we use the srp function in scapy to send and receive packets.
    #srp returns 2 types of packets.
    #They are the answered packets and unanswered packets.
    #We only care about answered packets 
    answered_packets = srp(arp_broadcast_packet, timeout=3, verbose=0)[0]

    #In each packet in the answered_packets list,
    #the IP address is stored in psrc variable
    #and the MAC address is stored in hwsrc variable
    #Store these values in a list of hosts
    
    if(oneMac):
        try:
            mac= answered_packets[0][1].hwsrc #mac location in packet
            # print(mac)
            return mac
        except: #IndexError:
            #maybe fake IP or firewall (Apple devices) is blocking packets
            # print('No Mac found for',ip)
            return None
    else:
        print("\nYour Network:")
        hosts = []
        for sent_packet,received_packet in answered_packets:
            hosts.append({'ip': received_packet.psrc, 'mac': received_packet.hwsrc})

        #print ARP table that contains available hosts on the network
        print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
        for host in hosts:
            print("{}\t{}".format(host['ip'], host['mac']))
        return(hosts)
    
"""
Author: Aline Challita
Function is tested
"""
def checkForDuplicateMacs(entries):
    """
    ----------------Function Description------------------------
    This function tests for duplicate MAC addresses in the table
    of IP-MAC bindings of all the hosts on the network.
    Since MAC addresses are unique,
    then if identical MAC addresses are found in the table,
    ARP cache poisoning is detected
    ------------------------------------------------------------ 
    """
    macarr = []                         #initialize empty array to store MAC addresses
    for entry in entries:
        macarr.append(entry['mac'])     #Fill MAC array with MAC entries from the table

    print("\nThe MAC entries in the table are:\n",macarr)
    print("\nInitiated testing for identical MAC addresses in table of IP-MAC bindings.") 
    
    d = {}                              #initialize empty dictionary
    dup_count = 0                       #initialize counter for duplicates
    
    #The dictionary stores each MAC address and its count
    #When a duplicate MAC address is encountered,
    #increase its count in the dictionary
    for mac in macarr:
        if (mac in d):
            d[mac]+=1
            dup_count+=1
        else:
            d[mac]=1

    if (dup_count == 0):
        print("No duplicate MAC addresses detected.")
    else:
        print("Warning! Identical MAC addresses have been detected in the table.")
        print("There might be an ARP cache poisoning attack on the network!")
        duplicates = dict((k, v) for k, v in d.items() if v > 1)
        print (duplicates)


#Author: Edmond Samaha
def getArpTable():
    command = ['arp', '-a']
    subprocess.call(command)    

#Author: Edmond Samaha
def checkMac(packet): #used with sniff() which is a Scapy specific function 
     global numarp
     if packet.haslayer(ARP): # if it is an ARP response (ARP reply)
        numarp+=1
        #Scapy encodes the type of ARP packet in a field called "op" which stands for operation, by default the "op" is 1 or "who-has" which is an ARP request, and 2 or "is-at" is an ARP reply
        if packet[ARP].op == 2: #check ARP replies (op=2)
            try:
                ip =packet[ARP].psrc
                real_mac = getMacs(ip) # get the real MAC address of the sender
                if(real_mac==None):
                    #print("[*] No MAC found for",ip)
                    return
                response_mac = packet[ARP].hwsrc # get the MAC address from the packet sent to us
                if real_mac != response_mac: # if they're different, there is an attack
                    print(f"[*] Fake arp detected:\n REAL-MAC: {real_mac.upper()}, FAKE-MAC: {response_mac.upper()}")
            except:
                print("Couldn't check MAC of",ip)

#Author: Edmond Samaha
def Detect(duration=10):
    start_time=datetime.now()
    print("Started at",start_time)
    print('Sniffing and checking...')
    
    """ For Scapy specific funtions below
    prn=checkMac runs checkMac for every packet (of course we focus on ARP packets as set in the function)
    store=False means don't save the packets
    """
    # sniff(store=False, prn=checkMac) #Scapy specific, ^C to stop, can also add filter="arp" as param
    #Asynchronous to implement time:
    t = AsyncSniffer(prn=checkMac, store=False)
    t.start()
    time.sleep(duration)
    t.stop()
    # print('Results:\n',t.results) #store=False so no output + no need
    print(numarp,'ARP packets were detected')

    print('\nStopped. Time taken:', datetime.now()-start_time)
#endregion

#RUN HERE
if __name__ == "__main__":
    
    #region Author: Aline
    #prompt user to input target IP of router with subnet mask
    target_ip =  input("Enter Target IP: ")
    IP_MAC_entries = getMacs(target_ip,False)
    checkForDuplicateMacs(IP_MAC_entries)
    #endregion

    #region Author: Edmond
    print('\nYour current ARP table:',end='')
    getArpTable()

    print('\n')
    duration=input('Enter how many SECONDS you would like to sniff packets:\n')
    while(type(duration)!=int or duration<1):
        try:
            duration=int(duration)
            if(duration<1):
                duration=int(input("Please enter a positive integer: "))
        except:
            duration=input("Please enter an integer: ")
    # print(duration)
    Detect(duration)
    #endregion
   
