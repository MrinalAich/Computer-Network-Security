from Tkinter import *
from datetime import datetime, time as dTime
import socket, struct, textwrap, binascii
import shlex, subprocess, array
import sys, tkMessageBox, time, threading
import matplotlib.pyplot as plt

Interface102 = "ens38" # 102 subnet interface to capture from
Interface103 = "ens39" # 103 subnet interface to capture from
ETH_P_ALL = 3 		   # To receive all Ethernet protocols
BUF_SIZE = 65536
DEBUG = 0

# Policy Actions
ACCEPT = 1
DROP = 0
REJECT = 2

myIntf102 = "192.168.102.101"
myIntf103 = "192.168.103.101"

clientAt102 = "192.168.102.102"
clientAt103 = "192.168.103.103"

# Interface Sockets
sock102 = ""
sock103 = ""

# List of clients to handle
clientsIPList  = [clientAt102, clientAt103]
clientsMACList = []

# Data Structures
arpDict  = {} # ARP Dictionary
ruleSet  = {} # RuleSet Dictionary
PSRecord = {} # Port Scan Attack Dictionaries
PSMark   = {}

# Port Scan parameters
timeInterval = 1 # In mins
thresFreq = 2

# Default Policy
INPUT_POLICY  = ACCEPT
OUTPUT_POLICY = ACCEPT

#Initialize pps and statistics
pps = [0]*100000
SUCCESS = 1
FAILURE = 0
pkt_cnt = 0
l2_pkt_cnt = 0 
l3_pkt_cnt = 0 
l4_pkt_cnt = 0 
drop_pkt_cnt = 0 

#Time Elapsed
timeE = 0
#Maximum Seconds it can handle 
maxSeconds = 100000000000

def initRuleSet():
    global arpDict, ruleSet
    chains = ['INPUT', 'OUTPUT']

    for chain in chains:
        ruleSet[chain] = {}

        ruleSet[chain]['L2'] = []
        ruleSet[chain]['L3'] = {}
        ruleSet[chain]['L4'] = {}

        ruleSet[chain]['L3']['ICMP'] = []
        ruleSet[chain]['L3']['IPv4'] = []
        ruleSet[chain]['L3']['IPv6'] = []

        ruleSet[chain]['L4']['TCP'] = []
        ruleSet[chain]['L4']['UDP'] = []

    if 0:
        # Random Rules
        #ruleSet['INPUT']['L2'].append((arpDict[clientAt103], "*"))
        #ruleSet['OUTPUT']['L2'].append(("*", arpDict[clientAt102]))

        #ruleSet['INPUT']['L3']['ICMP'].append((clientAt102,"*"))
        #ruleSet['INPUT']['L3']['ICMP'].append(("*","192.168.103.32/24"))
        ruleSet['INPUT']['L3']['IPv4'].append(("192.168.102.32/24","*"))

        #ruleSet['OUTPUT']['L3']['ICMP'].append(("*",clientAt102))

        #ruleSet['INPUT']['L4']['TCP'].append(("5555", "*"))

def main():
    global arpDict,pps,timeE, clientsMACList
    global pkt_cnt,l2_pkt_cnt,l3_pkt_cnt,l4_pkt_cnt,drop_pkt_cnt

    arpDict = getARPTable()
    for clientIP in clientsIPList:
        clientsMACList.append(arpDict[clientIP])
    
    initRuleSet()
    
    #Initialize Packet Count 
    pkt_cnt = 0 
    srcIP = ""
    start = time.time()
    sock102, sock103 = initSockets()

	# Analyse only 2 packets as of now
    while 1:

        try:
            packet = sock102.recv(BUF_SIZE)
        except:
            try:
                packet = sock103.recv(BUF_SIZE)
            except:
                continue

        # Assuming all Layer-2 packets as Ethernet frames
        if len(packet) > 14:

            # Maintaining the original packet
            origPacket = packet

            # Handle Ethernet Packet
            srcMAC,dstMAC,layer3Proto,packet = eth_header(packet)

            if srcMAC not in clientsMACList and dstMAC not in clientsMACList:
                continue

            pkt_cnt = pkt_cnt + 1

                # Check Output Policy Chain
            if True != checkL2Policy(srcMAC, dstMAC, "INPUT"):
                print "L2 Input Packet Dropped"
                drop_pkt_cnt = drop_pkt_cnt +1 
                l2_pkt_cnt = l2_pkt_cnt + 1
                continue

            # Handle ARP


            protocolL3 = []
            # Handle IPv4 Packet
            if layer3Proto == "0800":
                protocolL3.append('IPv4')

                ver,hdrLen,ttl,upperLayer3Proto,srcIP,dstIP,packet = ipv4_header(packet)
                if srcIP in clientsIPList and dstIP in clientsIPList:

                    # Handle IPv4
                    if SUCCESS != checkL3Policy(['IPv4'], srcIP, dstIP, "INPUT"):
                        print "L3 Input Packet Dropped"
                        drop_pkt_cnt = drop_pkt_cnt + 1 
                        l3_pkt_cnt = l3_pkt_cnt + 1 
                        continue

                    # Handle ICMP
                    if upperLayer3Proto == 1:
                        protocolL3.append('ICMP')
                        l3_pkt_cnt = l3_pkt_cnt + 1 
                        if SUCCESS != checkL3Policy(['ICMP'], srcIP, dstIP, "INPUT"):
                            print "L3 Input Packet Dropped"
                            drop_pkt_cnt = drop_pkt_cnt + 1 
                            continue

                    # Handle TCP and UDP
                    protocolL4 = ""
                    srcPort = ""
                    dstPort = ""
                    if upperLayer3Proto == 6 or upperLayer3Proto == 17:
                        srcPort,dstPort = tcp_udp_header(packet[:8])
                        if upperLayer3Proto == 6:
                            protocolL4 = 'TCP'
        
                            # Maintaing Context for the request
                            maintainContextForTCPPacket(packet, srcIP, dstIP, srcPort, dstPort)
                        else:
                            protocolL4 = 'UDP'

                        if SUCCESS != checkL4Policy(protocolL4, srcPort, dstPort, "INPUT"):
                            drop_pkt_cnt = drop_pkt_cnt + 1 
                            l4_pkt_cnt = l4_pkt_cnt + 1
                            print "L4 Input Packet Dropped"
                            continue

                    else:
                        l3_pkt_cnt = l3_pkt_cnt + 1
                    updateStatistics(start)
                    relayPackets(origPacket, sock102, sock103, protocolL3, srcIP, dstIP, protocolL4, srcPort, dstPort )
                    continue

        

# -----------------------------------------------------------------------------------------------

# ----- Filtering Functions -----

# Function matches L2 Input Chain policy rules
def checkL2Policy(src, dst, policyChain):
    global arpDict, ruleSet, INPUT_POLICY, OUTPUT_POLICY
    match  = 0

    if policyChain == "INPUT":
        POLICY = INPUT_POLICY
    else:
        POLICY = OUTPUT_POLICY

    # No action as rules are not specified
    if ruleSet[policyChain]['L2'] is None:
        print "None " + str(src) + " to " + str(dst) + " | " + str(POLICY)
        return (POLICY)

    else:
        #print "L2 To Match: |%s||%s| | Rules:%s" % (src,dst,str(ruleSet[policyChain]['L2']))
        for tup in ruleSet[policyChain]['L2']:
            
            # Check if a rule matches in the existing ruleSet
            if (tup[0] == "*" or tup[0] == src) and (tup[1] == "*" or tup[1] == dst):
                match = 1
                break

        if match:
            print "L2 Match:|%s| |%s->%s| | Rules:%s->%s" % (policyChain,src,dst,tup[0],tup[1])
            return (not POLICY)
        else:
            return (POLICY)

def matchIPPrefix(prefixIP, matchIP):
    prefixBin = ""
    matchBin = ""

    prefix = int(prefixIP.split('/')[1])

    for dec in prefixIP.split('/')[0].split("."):
        prefixBin = prefixBin + bin(int(dec))[2:].zfill(8)

    for dec in matchIP.split("."):
        matchBin = matchBin + bin(int(dec))[2:].zfill(8)

    return (prefixBin[:prefix] == matchBin[:prefix])

# Function matches L3 policy rules
def checkL3Policy(protocolList, src, dst, policyChain):
    global arpDict, ruleSet, INPUT_POLICY, OUTPUT_POLICY
    match  = 0
    srcMatch = 0
    dstMatch = 0

    if policyChain == "INPUT":
        POLICY = INPUT_POLICY
    else:
        POLICY = OUTPUT_POLICY

    for protocol in protocolList:
        
        # No action as rules are not specified
        if ruleSet[policyChain]['L3'][protocol] is None:
            continue
                
        else:
            for tup in ruleSet[policyChain]['L3'][protocol]:
                srcMatch = 0
                dstMatch = 0

                # Check if a rule matches in the existing ruleSet
                # Handle IP prefixes
                if '/' in tup[0]:
                    srcMatch = matchIPPrefix(tup[0], src)
                else:
                    srcMatch = (tup[0] == "*" or tup[0] == src)

                if '/' in tup[1]:
                    dstMatch = matchIPPrefix(tup[1], dst)
                else:
                    dstMatch = (tup[1] == "*" or tup[1] == dst)

                if srcMatch and dstMatch:
                    print "L3 Match:|%s %s| |%s->%s| | Rules:%s->%s" % (policyChain,protocol,src,dst,tup[0],tup[1])
                    # Opposite action as rule matched
                    return (not POLICY)
    
    # Default action no rule matched
    return (POLICY)

# Function matches L4 policy rules
def checkL4Policy(protocol, src, dst, policyChain):
    global arpDict, ruleSet, INPUT_POLICY, OUTPUT_POLICY
    match  = 0

    if policyChain == "INPUT":
        POLICY = INPUT_POLICY
    else:
        POLICY = OUTPUT_POLICY

    # Default action as rules are not specified
    if ruleSet[policyChain]['L4'][protocol] is None:
            return (POLICY)
    else:
        for tup in ruleSet[policyChain]['L4'][protocol]:
            
            # Check if a rule matches in the existing ruleSet
            if (tup[0] == "*" or tup[0] == str(src)) and (tup[1] == "*" or tup[1] == str(dst)):
                if DEBUG:
                    print "L4 Match:|%s %s| |%s->%s| | Rules:%s->%s" % (policyChain,protocol,src,dst,tup[0],tup[1])
                match = 1
                break

        if match:
            # Opposite action as rule matched
            return (not POLICY)
        else:
            # Default action no rule matched
            return (POLICY)

# ----- Utility functions -----

# Function relays the Packets depending on the Src and Dst IP Addresses
def relayPackets(origPacket, sock102, sock103, protocolL3, srcIP, dstIP, protocolL4, srcPort, dstPort):

    # Relay over 103-subnet
    if srcIP == clientAt102 and dstIP == clientAt103:
        sendPacket(origPacket, sock103, protocolL3, myIntf103, clientAt103, protocolL4, srcPort, dstPort)

    # Relay over 102-subnet
    elif srcIP == clientAt103 and dstIP == clientAt102:
        sendPacket(origPacket, sock102, protocolL3, myIntf102, clientAt102, protocolL4, srcPort, dstPort)

# Function sends a packet over an interface with srcIP and dstIP
def sendPacket(packet, sock, protocolL3List, srcIP, dstIP, protocolL4, srcPort, dstPort):
    global arpDict   
    packetLen = len(packet)

    # Check Output Policy Chains
    ## Layer 2
    if True != checkL2Policy(arpDict[srcIP], arpDict[dstIP], "OUTPUT"):
        print "L2 Output Packet Dropped"
        return

    ## Layer 3
    if SUCCESS != checkL3Policy(protocolL3List, srcIP, dstIP, "OUTPUT"):
        print "L3 Output Packet Dropped"
        return

    ## Layer 4
    if protocolL4 != "":
        if SUCCESS != checkL4Policy(protocolL4, srcPort, dstPort, "OUTPUT"):
            print "L4 Output Packet Dropped"
            return

    # Modify Dst MAC Address (Acting as a router)
    srcMAC = arpDict[srcIP].replace(':', '')
    dstMAC = arpDict[dstIP].replace(':', '')

    buffer = array.array('c', ' ' * packetLen)
    struct.pack_into('!6s6s%ds' % (packetLen-12), buffer, 0, binascii.unhexlify(dstMAC), binascii.unhexlify(srcMAC), packet[12:packetLen])

    if 0 == sock.send(buffer):
        print "Unable to send Packet from %s to %s" % (srcIP,dstIP)

# Function retreives the ARP table of the system
def getARPTable():
    arpDict = {}
    arpDict[myIntf102] = "00:50:56:3c:89:08"
    arpDict[myIntf103] = "00:50:56:22:f6:7d"

    cmd = "arp -n | awk '{if (NR!=1) print $1\" \"$3}'"

    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)                               
    output, errors = p.communicate()
    if output is not None:
        lines = output.split("\n")
        for iter in range(0,len(lines)-1):
            line = lines[iter]
            addrs = line.split(" ")
            arpDict[addrs[0]] = addrs[1]

    return arpDict

#Unpacks Ethernet Header
def eth_header(data):
    ethH = struct.unpack("!6s6s2s",data[:14])
    dstMAC = getMACAddr(ethH[0])
    srcMAC = getMACAddr(ethH[1])
    layer3Proto = str(binascii.hexlify(ethH[2]).decode())

    return srcMAC,dstMAC,layer3Proto,data[14:]

#Unpacks IPv4 Header
def ipv4_header(data):
    version_header_length = ord(data[0])
    version = version_header_length >> 4 
    header_length = (version_header_length & 15)*4
    ttl,proto,src,target = struct.unpack('!8xBB2x4s4s', data[:20])
    return version,header_length,ttl,proto,getIPAddr(src),getIPAddr(target),data[header_length:]

#Unpacks IMCP Header
def icmp_header(data):
    icmp_type = struct.unpack('!B3x',data[:4])
    return icmp_type

#Unpacks TCP Header
def tcp_udp_header(data):
    port = struct.unpack("!HH%dx" % (len(data)-4), data)
    return port[0],port[1]

def getMACAddr(ethData):
    return ':'.join([str(binascii.hexlify(a).decode()) for a in ethData])

def getIPAddr(ipData):
    return '.'.join([str(ord(a)) for a in ipData])

# Function Open sockets over the two interfaces
def initSockets():

    sock102 = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(ETH_P_ALL))
    sock102.bind((Interface102, ETH_P_ALL))
    sock102.setblocking(0)

    sock103 = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(ETH_P_ALL))
    sock103.bind((Interface103, ETH_P_ALL))
    sock103.setblocking(0)

    return sock102,sock103

# Function updates the statistics
def updateStatistics(startTime):
    global timeE, pps
        
    stopTime = time.time()
    if int(stopTime - startTime) != 0:
        timeE = int(stopTime-startTime)
        if pps[timeE] != 0 :
            return
        if timeE == 1:
             pps[timeE] = pkt_cnt
        elif timeE < maxSeconds: 
             pps[timeE] = pkt_cnt - pps[timeE-1]
        else : 
             return      

# ----- Port Scan -----

# Function maintaing Context for the request
def maintainContextForTCPPacket(packet, srcIP, dstIP, srcPort, dstPort):
    
    '''
    Note Time
    Check for the type of Header

    If Rcvd: SYN
        If context for (IP, Time) in Recode not present:
            Record[(IP,Time)] = 1

    Elif Rcvd: RST
        If context for (IP, Time) in Mark not present:
            Mark[(IP,Time)] = ++1

    Elif Rcvd: SYN+ACK
        # Connection established
        Remove Record[(IP,Time)]
    '''

    # Check for the type of TCP Flags
    ack,rst,syn = getTCPFlags(packet[13])
    if DEBUG:
        print "ack:" + str(ack) + " rst:" + str(rst) + " syn:" + str(syn)

    # If Rcvd: SYN
    if syn:
        # If context for (IP, Time) in Record not present:
        if (srcIP,dstIP) not in PSRecord:
            PSRecord[(srcIP,dstIP)] = {}
            PSRecord[(srcIP,dstIP)][dstPort] = 0

        elif dstPort not in PSRecord[(srcIP,dstIP)]:
            PSRecord[(srcIP,dstIP)][dstPort] = 0

        # Maintains No. of SYN Connections
        PSRecord[(srcIP,dstIP)][dstPort] = PSRecord[(srcIP,dstIP)][dstPort] + 1
        if DEBUG:
            print "Record added: %s->%s | Port:%s" % (srcIP,dstIP,dstPort)

    # If Rcvd: RST
    elif rst:
        if (dstIP,srcIP) in PSRecord:
            if srcPort in PSRecord[(dstIP,srcIP)]:
                # Remove a record from PSRecord
                PSRecord[(dstIP,srcIP)][srcPort] = PSRecord[(dstIP,srcIP)][srcPort] - 1
                if DEBUG:
                    print "RST Record removed: %s->%s | Port:%s" % (dstIP,srcIP,srcPort)

                # Remove entry
                if PSRecord[(dstIP,srcIP)][srcPort] == 0:
                    del PSRecord[(dstIP,srcIP)][srcPort]

                # Add into Mark
                ## Note Time
                currentTime = getTimeInMinutes()
                if (dstIP,srcIP) not in PSMark:
                    PSMark[(dstIP,srcIP)] = {}
                    PSMark[(dstIP,srcIP)][currentTime] = 0

                elif currentTime not in PSMark[(dstIP,srcIP)]:
                    PSMark[(dstIP,srcIP)][currentTime] = 0

                # Maintain record for all RST connections
                PSMark[(dstIP,srcIP)][currentTime] = PSMark[(dstIP,srcIP)][currentTime] + 1
                if DEBUG:
                    print "Mark added: %s->%s | Port:%s at %s" % (dstIP,srcIP,srcPort,currentTime)


                if SUCCESS == detectPortScan(dstIP):
                    # Block the IP Address
                    ruleSet['INPUT']['L3']['IPv4'] = [(dstIP, "*")]
                    print "Port Scan detected. Blocked IP Address: " + str(dstIP)

    # If Rcvd: ACK
    elif ack:
        if (dstIP,srcIP) in PSRecord:
            if srcPort in PSRecord[(dstIP,srcIP)]:
                # Remove a record from PSRecord
                PSRecord[(dstIP,srcIP)][srcPort] = PSRecord[(dstIP,srcIP)][srcPort] - 1
                if DEBUG:
                    print "ACK Record removed: %s->%s | Port:%s" % (dstIP,srcIP,srcPort)

                # Remove entry
                #if PSRecord[(dstIP,srcIP)][srcPort] == 0:
                #    del PSRecord[(dstIP,srcIP)][srcPort]

# Function detects Port Scan attack over the a recorded interval of time
def detectPortScan(ipAddr):
    global PSMark, timeInterval, thresFreq

    currentTime = getTimeInMinutes()
    counter = 0
    for srcIP,dstIP in PSMark:
        if srcIP == ipAddr:
            for loggedTime in PSMark[(srcIP,dstIP)]:
                rstCnt = PSMark[(srcIP,dstIP)][loggedTime]

                if currentTime - loggedTime < timeInterval:
                    counter = counter + rstCnt
                    #else:
                    # Delete the useless data
                    #del PSMark[(srcIP,dstIP)][loggedTime]

    # Port Scanning detected
    return (counter > thresFreq)
    

# Function returns specific flags of TCP
def getTCPFlags(byteVal):
    ack = ((ord(byteVal) & (1<<4)) != 0)
    rst = ((ord(byteVal) & (1<<2)) != 0)
    syn = ((ord(byteVal) & (1<<1)) != 0)

    return ack,rst,syn


# Retreives minutes elapsed since Midnight
def getTimeInMinutes():
    utcnow = datetime.utcnow()
    midnight_utc = datetime.combine(utcnow.date(), dTime(0))
    delta = utcnow - midnight_utc
    return delta.seconds/60 # <-- careful

# ----- GUI Class -----
class firewallGUI(threading.Thread):

    #Initializing The Values 
    dropInputVal = ""
    dropOutputVal = ""

    #Initialize Layer 2 Variables 
    dropL2ChainVal = ""
    textSrcMAC = ""
    textDstMAC = ""

    #Initialize Layer 3 Variables 
    dropL3ChainVal = ""
    protocolL3Val = ""
    textSrcIP = ""
    textDstIP = ""
    protocolL3Val = ""

    #Initialize Layer 4 Variables 
    dropL4ChainVal = ""
    protocolL4Val = ""
    textSrcPort = ""
    textDstPort = ""

    def __init__(self):
        threading.Thread.__init__(self)
        self.start()

    def callback(self):
        self.root.quit()

    def handlerLayer2(self):
        global ruleSet
        srcMAC = str(self.textSrcMAC.get('1.0', 'end').strip())
        dstMAC = str(self.textDstMAC.get('1.0', 'end').strip())

        res,srcMAC,dstMAC = self.sanityCheckForInput('L2', srcMAC, dstMAC)
        if res != SUCCESS:
            tkMessageBox.showinfo("Invalid Input.","Go, learn Networks first!!!")
            return

        chain  =  self.dropL2ChainVal.get().strip()
        if chain == 'BOTH':

            for ch in ['INPUT', 'OUTPUT']:
                ruleSet[ch]['L2'].append((srcMAC, dstMAC))

        else:
            ruleSet[chain]['L2'].append((srcMAC, dstMAC))

    def handlerLayer3(self):
        global ruleSet
        chain = self.dropL3ChainVal.get()
        protocolL3 = self.protocolL3Val.get()
        srcIP = self.textSrcIP.get('1.0', 'end').strip()
        dstIP = self.textDstIP.get('1.0', 'end').strip()

        res,srcIP,dstIP = self.sanityCheckForInput('L3', srcIP, dstIP)
        if res != SUCCESS:
            tkMessageBox.showinfo("Invalid Input.","Go, learn Networks first!!!")
            return

        if chain == 'BOTH':
            for ch in ['INPUT', 'OUTPUT']:
                ruleSet[ch]['L3'][protocolL3].append((srcIP, dstIP))

        else:
            ruleSet[chain]['L3'][protocolL3].append((srcIP, dstIP))

    # Function handles port range
    def checkPortRange(self,portString):
        ports = []

        if portString == "":
            return SUCCESS,['*']

        # Check for valid chars
        validCharList = []
        for x in range(0,10):
            validCharList.append(str(x))

        portList = portString.split(",")
        for portStr in portList:

            # Split with '-'
            if "-" in portStr:
                portRange = portStr.split("-")

                for rang in portRange:
                    for char in rang:
                        if str(char) not in validCharList:
                            print "L4: " + str(char)
                            return FAILURE,[]
                start = int(portRange[0])
                end   = int(portRange[1])

                for port in range(start, end+1):
                    ports.append(str(port))
            else:

                for char in portStr:
                    if str(char) not in validCharList:
                        print "L4: " + str(char)
                        return FAILURE,[]
                ports.append(portStr)

        return SUCCESS,ports

    def handlerLayer4(self):
        global ruleSet
        chain = self.dropL4ChainVal.get()
        protocolL4 = self.protocolL4Val.get()
        srcPortString =  self.textSrcPort.get('1.0', 'end').strip()
        dstPortString = self.textDstPort.get('1.0', 'end').strip()

        # Handles Port Range
        result, srcPortList = self.checkPortRange(srcPortString)
        if result != SUCCESS:
            print "srrc %s" % (srcPortString)
            tkMessageBox.showinfo("Invalid Input.","Go, learn Networks first!!!")
            return

        result, dstPortList = self.checkPortRange(dstPortString)
        if result != SUCCESS:
            print "dst %s" % (dstPortString)
            tkMessageBox.showinfo("Invalid Input.","Go, learn Networks first!!!")
            return

        for srcPort in srcPortList:
            for dstPort in dstPortList:

                res,srcPort,dstPort = self.sanityCheckForInput('L4', srcPort, dstPort)
                if res != SUCCESS:
                    tkMessageBox.showinfo("Invalid Input.","Go, learn Networks first!!!")
                    return

                if chain == 'BOTH':
                    for ch in ['INPUT', 'OUTPUT']:
                        ruleSet[ch]['L4'][protocolL4].append((srcPort, dstPort))
                else:
                    ruleSet[chain]['L4'][protocolL4].append((srcPort, dstPort))
            
    def handlerInputPolicy(self):
        global INPUT_POLICY, ruleSet
        if self.dropInputVal.get().strip() == "ACCEPT":
            INPUT_POLICY = ACCEPT
        else:
            INPUT_POLICY = DROP

        ruleSet['INPUT']['L2'] = []
        ruleSet['INPUT']['L3'] = {}
        ruleSet['INPUT']['L4'] = {}

        ruleSet['INPUT']['L3']['ICMP'] = []
        ruleSet['INPUT']['L3']['IPv4'] = []
        ruleSet['INPUT']['L3']['IPv6'] = []

        ruleSet['INPUT']['L4']['TCP'] = []
        ruleSet['INPUT']['L4']['UDP'] = []

    def handlerOutputPolicy(self):
        global OUTPUT_POLICY, ruleSet
        if self.dropOutputVal.get().strip() == "ACCEPT":
            OUTPUT_POLICY = ACCEPT
        else:
            OUTPUT_POLICY = DROP

        ruleSet['OUTPUT']['L2'] = []
        ruleSet['OUTPUT']['L3'] = {}
        ruleSet['OUTPUT']['L4'] = {}

        ruleSet['OUTPUT']['L3']['ICMP'] = []
        ruleSet['OUTPUT']['L3']['IPv4'] = []
        ruleSet['OUTPUT']['L3']['IPv6'] = []

        ruleSet['OUTPUT']['L4']['TCP'] = []
        ruleSet['OUTPUT']['L4']['UDP'] = []

    def handlerShowStats(self):
        global pkt_cnt,drop_pkt_cnt,l2_pkt_cnt,l3_pkt_cnt,l4_pkt_cnt
        global timeE
        print "Showing  Statistics"
        print "Total Packets: " + str(pkt_cnt)
        print "Dropped Packet Count: " + str(drop_pkt_cnt)
        print "L2_Packet matched to rules: " + str(l2_pkt_cnt) 
        print "L3_Packet matched to rules: " + str(l3_pkt_cnt)
        print "L4_Packet matched to rules: " + str(l4_pkt_cnt)
        print "Time Elapsed: " + str(timeE)
        
        plt.plot([k for k in range(0,timeE)],[int(pps[k]) for k in range(0,timeE)])
        plt.axis([int(0),int(timeE+5),int(pps[0]-2),int(pps[timeE]+2)])
        plt.xlabel("No. of time elapsed (in seconds)")
        plt.ylabel("Packets processed")
        plt.title("Packets processed per second (pps)")
        plt.savefig("myplot" + ".png")
        plt.close()

    # Policy Frame
    def createPolicyFrame(self):
        # Input Policy
        self.InputPolicyFrame = Frame(self.root, width=1000, height=10)
        labelInput = Label(self.InputPolicyFrame, text="Input Policy  ")
        labelInput.pack(fill=X, side=LEFT)

        ## Drop down Menu
        self.dropInputVal = StringVar(self.root)
        self.dropInputVal.set("ACCEPT")

        optionInput = OptionMenu(self.InputPolicyFrame, self.dropInputVal, "ACCEPT", "DROP", "REJECT")
        optionInput.pack(fill=X, side=LEFT)

        button = Button(self.InputPolicyFrame, text="OK", command=self.handlerInputPolicy)
        button.pack(fill=X, side=RIGHT)

        self.InputPolicyFrame.pack(fill=Y, side=TOP)

        # Output Policy
        self.OutputPolicyFrame = Frame(self.root, width=1000, height=10)
        labelOutput = Label(self.OutputPolicyFrame, text="Output Policy")
        labelOutput.pack(fill=X, side=LEFT)

        ## Drop down Menu
        self.dropOutputVal = StringVar(self.root)
        self.dropOutputVal.set("ACCEPT")

        optionOutput = OptionMenu(self.OutputPolicyFrame, self.dropOutputVal, "ACCEPT", "DROP", "REJECT")
        optionOutput.pack(fill=X, side=LEFT)

        button = Button(self.OutputPolicyFrame, text="OK", command=self.handlerOutputPolicy)
        button.pack(fill=X, side=RIGHT)

        self.OutputPolicyFrame.pack(fill=Y, side=TOP)

    # Layer-2 Frame
    def createLayer2Frame(self):
        
        self.Layer2Frame = Frame(self.root, width=1000, height=10)
        labelLayer2 = Label(self.Layer2Frame, text="Layer-2 ")
        labelLayer2.pack(fill=X, side=LEFT)

        ## Drop down Chain Menu
        self.dropL2ChainVal = StringVar(self.root)
        self.dropL2ChainVal.set("BOTH")
        self.optionL2Chain = OptionMenu(self.Layer2Frame, self.dropL2ChainVal, "BOTH  ", "INPUT", "OUTPUT")
        self.optionL2Chain.pack(fill=X, side=LEFT)

        ## Src MAC
        self.srcMACFrame = Frame(self.Layer2Frame, width=10, height=1)
        self.textSrcMAC = Text(self.srcMACFrame, width=10, height=1)
        self.textSrcMAC.pack(side=TOP)


        labelSrcMAC = Label(self.srcMACFrame, text="Src MAC")
        labelSrcMAC.pack(fill=X, side=TOP)
        self.srcMACFrame.pack(fill=X, side=LEFT)

        ## Dst MAC
        self.dstMACFrame = Frame(self.Layer2Frame, width=10, height=1)
        self.textDstMAC = Text(self.dstMACFrame, width=10, height=1)
        #self.textDstMAC.get()
        self.textDstMAC.pack(side=TOP)

        labelDstMAC = Label(self.dstMACFrame, text="Dst MAC")
        labelDstMAC.pack(fill=X, side=TOP)
        self.dstMACFrame.pack(fill=X, side=LEFT)
        
        button = Button(self.Layer2Frame, text="OK", command=self.handlerLayer2)
        button.pack(fill=X, side=RIGHT)

        self.Layer2Frame.pack(fill=X, side=TOP)

    # Layer-3 Frame
    def createLayer3Frame(self):

        self.Layer3Frame = Frame(self.root, width=1000, height=1)
        labelLayer3 = Label(self.Layer3Frame, text="Layer-3 ")
        labelLayer3.pack(fill=X, side=LEFT)
        
        ## Drop down Chain Menu
        self.dropL3ChainVal = StringVar(self.root)
        self.dropL3ChainVal.set("BOTH")
        optionL3Chain = OptionMenu(self.Layer3Frame, self.dropL3ChainVal, "BOTH", "INPUT", "OUTPUT")
        optionL3Chain.pack(fill=X, side=LEFT)

        ## Drop down Menu
        self.protocolL3Val = StringVar(self.root)
        self.protocolL3Val.set("ICMP")

        optionProtoL3 = OptionMenu(self.Layer3Frame, self.protocolL3Val, "ICMP", "IPv4", "IPv6")
        optionProtoL3.pack(fill=X, side=LEFT)

        ## Src IP
        self.srcIPFrame = Frame(self.Layer3Frame, width=10, height=1)
        self.textSrcIP = Text(self.srcIPFrame, width=10, height=1)
        self.textSrcIP.pack(side=TOP)

        labelSrcIP = Label(self.srcIPFrame, text="Src IP")
        labelSrcIP.pack(fill=X, side=TOP)
        self.srcIPFrame.pack(fill=X, side=LEFT)


        ## Dst IP
        self.dstIPFrame = Frame(self.Layer3Frame, width=10, height=1)
        self.textDstIP = Text(self.dstIPFrame, width=10, height=1)
        self.textDstIP.pack(side=TOP)

        labelDstIP = Label(self.dstIPFrame, text="Dst IP")
        labelDstIP.pack(fill=X, side=TOP)
        self.dstIPFrame.pack(fill=X, side=LEFT)

        button = Button(self.Layer3Frame, text="OK", command=self.handlerLayer3)
        button.pack(fill=X, side=RIGHT)

        self.Layer3Frame.pack(fill=X, side=TOP)


    # Layer-4 Frame
    def createLayer4Frame(self):
        self.Layer4Frame = Frame(self.root, width=1000, height=1)
        labelLayer4 = Label(self.Layer4Frame, text="Layer-4 ")
        labelLayer4.pack(fill=X, side=LEFT)

        ## Drop down Chain Menu
        self.dropL4ChainVal = StringVar(self.root)
        self.dropL4ChainVal.set("BOTH")
        optionL4Chain = OptionMenu(self.Layer4Frame, self.dropL4ChainVal, "BOTH", "INPUT", "OUTPUT")
        optionL4Chain.pack(fill=X, side=LEFT)

        ## Drop down Protocol Menu
        self.protocolL4Val = StringVar(self.root)
        self.protocolL4Val.set("TCP")

        optionProtoL4 = OptionMenu(self.Layer4Frame, self.protocolL4Val, "TCP", "UDP")
        optionProtoL4.pack(fill=X, side=LEFT)


        ## Src Port
        self.srcPortFrame = Frame(self.Layer4Frame, width=10, height=1)
        self.textSrcPort = Text(self.srcPortFrame, width=10, height=1)
        self.textSrcPort.pack(side=TOP)

        labelSrcPort = Label(self.srcPortFrame, text="Src Port")
        labelSrcPort.pack(fill=X, side=TOP)
        self.srcPortFrame.pack(fill=X, side=LEFT)


        ## Dst Port
        self.dstPortFrame = Frame(self.Layer4Frame, width=10, height=1)
        self.textDstPort = Text(self.dstPortFrame, width=10, height=1)
        self.textDstPort.pack(side=TOP)

        labelDstPort = Label(self.dstPortFrame, text="Dst Port")
        labelDstPort.pack(fill=X, side=TOP)
        self.dstPortFrame.pack(fill=X, side=LEFT)

        button = Button(self.Layer4Frame, text="OK", command=self.handlerLayer4)
        button.pack(fill=X, side=RIGHT)

        self.Layer4Frame.pack(fill=X, side=TOP)

    # Label Note
    def addNote(self, data, fontsize):
        labelNote = Label(self.root, text=data)
        labelNote.config(font=("Courier", fontsize))
        labelNote.pack(fill=X, side=TOP)

    # Show Statistics
    def showStatistics(self):
        statsButton = Button(self.root, text="Show Statistics", command=self.handlerShowStats)
        statsButton.pack(fill=X, side=TOP)

    # Add Separator
    def addSeparator(self):
        # Separator
        separator = Frame(self.root, height=2, bd=1, relief=SUNKEN)
        separator.pack(side=TOP, fill=X, padx=5, pady=5)

    # Function checks for Invalid Inputs
    def sanityCheckForInput(self, layer, src, dst):

        endList = []

        src = src.replace(" \\n", "")
        dst = dst.replace(" \\n", "")

        # Convert blank strings
        if src == "" or src == '*':
            src = '*'
        else:
            endList.append(src)

        if dst == "" or dst == '*':
            dst = '*'
        else:
            endList.append(src)

        #return SUCCESS,src,dst

        if layer == "L2":
            validCharList = []
            for x in range(48,58):
                validCharList.append(str(x))
            for x in range(97,103):
                validCharList.append(str(x))
            for x in range(65,71):
                validCharList.append(str(x))

            for mac in endList:
                # Check MAC Address len
                if len(mac) != 17:
                    print "L2: " + 'len'
                    return FAILURE,'',''

                # Check for invalid characters in address
                tempmac = mac.replace(":","")
                for char in tempmac:
                    if str(char) not in validCharList:
                        print "L2: " + str(char)
                        return FAILURE,'',''

                # Check for valid mac address
                if mac.count(':') != 5:
                    print "L2: " + ':'
                    return FAILURE,'',''

        elif layer == "L3":
            validCharList = []
            for x in range(0,10):
                validCharList.append(str(x))

            for ipAddr in endList:

                # Prefix IP addresses
                if "\\" not in ipAddr: 

                    # Check for valid IP address
                    if ipAddr.count('.') != 3:
                        print "L3: " + '...'
                        return FAILURE,'',''

                # Non-prefix IP Address
                else:
                    # Check IP Len:
                    if len(ipAddr) < 7 and len(ipAddr) > 15:
                        print "L3: " + 'len'
                        return FAILURE,'',''
                
                    # Check for invalid characters in address
                    tempIPAddr = ipAddr.replace(".", "")
                    for char in tempIPAddr:
                        if str(char) not in validCharList:
                            print "L3: " + str(char)
                            return FAILURE,'',''

                    # Check for valid IP address
                    if ipAddr.count('.') != 3:
                        print "L3: " + '...'
                        return FAILURE,'',''

                    # Check inter-dot chars
                    tempIP = ipAddr.split('.')
                    for char in tempIP:
                        if len(char) < 1 or len(char) > 3:
                            print "L3: " + "Inter-Len"
                            return FAILURE,'',''




        elif layer == "L4":
            validCharList = []
            for x in range(0,10):
                validCharList.append(str(x))
            
            # Check for valid Ports
            for port in endList:
                for char in port:
                    if str(char) not in validCharList:
                        print "L4: " + str(char)
                        return FAILURE,'',''

        return SUCCESS,src,dst

    # Main function
    def run(self):
        self.root = Tk()
        self.createPolicyFrame()
        self.addSeparator()

        self.createLayer2Frame()
        self.addSeparator()

        self.createLayer3Frame()
        self.addSeparator()

        self.createLayer4Frame()
        self.addSeparator()

        self.addNote("*Empty fields would be interpret as all(*)", 10)

        self.showStatistics()

        self.root.mainloop()

#if __name__ == "__main__": main()
gui = firewallGUI()
#gui.root.after(2000,main)
#gui.main()
#gui.handlerShowStats()
main()
print "Complete!!!"
