import socket
import sys
import ast
from abhilashlibraries import responseCodeMap, get_ip
import threading
import random

clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
UDP_IP_ADDRESS = ""
UDP_PORT_NO = 0    
sourceIP = get_ip()

program_name = sys.argv[0]
arguments = sys.argv[1:]
count = len(arguments)

request = {}

def sendRequest(request):
	global UDP_IP_ADDRESS, UDP_PORT_NO
	clientSock.sendto(request.encode(), (UDP_IP_ADDRESS, UDP_PORT_NO))
	
if count == 0:
	destinationIP = input("Enter destination IP : ")
	bandwidth = int(input("Enter bandwidth (Mbits/s) : "))
	duration = int(input("Enter time of connection : "))
	request = { 'rid':random.randint(1,99999), 'bandwidth':bandwidth, 'ip_src':sourceIP, 'ip_dst':destinationIP, 'timeout':duration}
	UDP_IP_ADDRESS = input("Default gateway : ")
	UDP_PORT_NO = int(input("Destination port number : "))
	sendRequest(str(request))
else:
	request = { 'rid':random.randint(1,99999), 'bandwidth':int(arguments[2]), 'ip_src':arguments[3], 'ip_dst':arguments[4], 'timeout':int(arguments[5])}
	print "rid"+str(request['rid'])
	UDP_IP_ADDRESS = arguments[0]
	UDP_PORT_NO = int(arguments[1])
	sendRequest(str(request))

print "\nWaiting for controller response ... "
serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSock.bind((sourceIP, 10000))
response, addr = serverSock.recvfrom(1024)

response = ast.literal_eval(response)
print "\n*---Response Start---*"
print "\nResponse Code : "+str(response["res"])+" , "+responseCodeMap[response["res"]]
print "\nRemaining Link Bandwidth : "+str(response["data"])
print "\n*---Response Close---*"
