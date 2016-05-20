#! /usr/bin/env python
# Project 3 : Network Scan Detection
# EECE 480F
# By: Tremayne Stewart
# Due May 22, 2016

from optparse import OptionParser
import sys
#When a computer is initially scanned by another there is an ARP request and reply sent through the switch/gateway
#To find who's scanning, Find the reply then use the replied IP addr to search back to the associated request
#(i.e)
#NMAP scans start with an ARP request and Reply sequence
#   16:19:18.192482 ARP, Request who-has 172.16.176.129 (Broadcast) tell 172.16.176.132, length 46
#   16:19:18.193068 ARP, Reply 172.16.176.129 is-at 00:0c:29:db:19:ad (oui Unknown), length 46
#   > In this example 172.16.176.129 is being scanned by 172.16.176.132
def checkLine(line):
    global sendCounter
    global scanType
    global scannerIP
    global time
    global detect
    if("ARP, Request" in line):
        #Store ARP, Request for future matches with Replies
        stdinBuffer.insert(0,line)

        if detect:
            if(sendCounter is 100): #Scan is -F
                scanType="-F"
            if(scanType is not ""):
                return "\tnmap %s from %s at %s\n" % (scanType,scannerIP,time)

    elif("ARP, Reply" in line):
        #clear scanType detection since we'll be checking from here till the next request
        scanType=""
        sendCounter=0
        #Get IP addr from line
        ip = line[line.find("ARP, Reply")+8:].split(" ")[1].strip()

        #Look back in stdinBuffer for the associated request
        for request in stdinBuffer:
            scannedIP,scannerIP = request.split("tell")
            scannerIP = scannerIP[:scannerIP.find(",")].strip()
            #Check for the reply IP address as the Request's who-has argument
            if(ip in scannedIP):
                time = scannedIP[:scannedIP.find(".")]
                stdinBuffer.remove(request)
                if not detect:
                    return "\tscanned from %s at %s\n" % (scannerIP,time)
    elif(detect): #Monitor other lines for key information
        line = line[line.find(">"):]
        if("[S]" in line):
            sendCounter+=1
        elif("ICMP echo request" in line): #Identifies if there was an -O scan done
            scanType="-O"
        elif("ICMP" in line and "udp port" in line):
            scanType="-sU"

if __name__ == "__main__":
    stdinBuffer=[]
    scannerIP=""
    time=""
    scanType=""
    sendCounter=0 #Counts the number of [S] requests done by NMAP to determin scan type ( if 100 then -F)
    parser = OptionParser()
    parser.add_option("--online", action="store_true", dest="live",help="Detects scanning in real time using pipelineing\n\t\tusage: some_command | python scanproject.py --online")
    parser.add_option("--detect", action="store_true", dest="detect",help="Tries to determine the type of [nmap] scans")


    detect = parser.parse_args()[0].detect #running in detect
    if(parser.parse_args()[0].live): #running in live mode
        #Run the line checker from stdin
        for line in sys.stdin:
            out = checkLine(line)
            if(out):
                print out
    else:
        #Find all log files in the working directory
        #iterate over them and all the lines in them
        #outputs results.txt in the form :
        # tcpdump0.log -->
        #    scanned from 192.168.100.15 at 01:49:07
        # tcpdump_junk.log -->
        #   scanned from 192.168.100.17 at 01:50:23
        #   scanned from 192.168.100.16 at 02:40:03
        results = open("results.txt","w")
        from glob import glob
        for fileName in glob("*.log"):
            stdinBuffer=[]
            results.write("%s -->\n" % fileName)
            #open file and stream data in
            #fileName = "tcpdump_nmap_sU.log"
            logFile = open(fileName,'r')
            for line in logFile:
                out=checkLine(line)
                if(out):
                    results.write(out)
