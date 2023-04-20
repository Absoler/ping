import threading
import struct
import socket
import re
import argparse
import os
import time
import signal

# def checkIp(ip):
#     ip_rule = re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
#     if ip_rule.match(ip):
#         return True
#     else:
#         return False

TIMEOUT = 1
timeout_mp:dict[int, int] = {}
lock = threading.Lock() # protect timeout_mp

def checksum(string) -> bytes:
    csum = 0      
    countTo = (len(string) // 2) * 2      
    count = 0           
    while count < countTo:         
        thisVal = string[count+1] * 256 + string[count]          
        csum = csum + thisVal         
        csum = csum & 0xffffffff         
        count = count + 2     
        
    if countTo < len(string):         
        csum = csum + string[len(string) - 1]        
        csum = csum & 0xffffffff      
    
    csum = (csum >> 16) + (csum & 0xffff)      
    csum = csum + (csum >> 16)     
    answer = ~csum     
    answer = answer & 0xffff      
    answer = answer >> 8 | (answer << 8 & 0xff00)      
    return struct.pack('!H', answer)

def calculate_checksum(icmp):
    if len(icmp) % 2:
        icmp += b'\00'

    checksum = 0
    for i in range(len(icmp)//2):
        word, = struct.unpack('!H', icmp[2*i:2*i+2])
        checksum += word

    while True:
        carry = checksum >> 16
        if carry:
            checksum = (checksum & 0xffff) + carry
        else:
            break

    checksum = ~checksum & 0xffff

    return struct.pack('!H', checksum)

def pack_icmp_forEchoRequest(ident:int, seq:int, payload:bytes):
    noCheckSum = struct.pack(
        '!BBHHH',
        8,
        0,
        0, # init 0 for checksum
        ident,
        seq,
    ) + payload
    checkSum = calculate_checksum(noCheckSum)
    return noCheckSum[:2] + checkSum + noCheckSum[4:]

def unpack_icmp_forEchoReply(icmp:bytes):
    Type, Code, _, ident, seq = struct.unpack('!BBHHH', icmp[:8])

    if Code != 0:
        return None
    if Type != 0:
        return None
    payload = icmp[8:]  # this payload is the same as the sent payload
    return ident, seq, payload


def send(sock:socket.socket, addr:str, ident:int):
    seq = 1
    while 1:
        curTime = time.time()
        payload = struct.pack('!d', curTime)
        icmp = pack_icmp_forEchoRequest(ident, seq, payload)
        
        sock.sendto(icmp, 0, (addr, 0))
        
        time.sleep(TIMEOUT)

        lock.acquire()
        if seq not in timeout_mp:
            timeout_mp[seq] = 1
        lock.release()

        seq += 1

def recv(sock:socket.socket):
    while 1:
        ip, (addr, _) = sock.recvfrom(1500)
        
        icmp = unpack_icmp_forEchoReply(ip[20:])

        if icmp is None:
            continue
    
        ident, seq, payload = icmp
        sendTime, = struct.unpack('!d', payload[:8])
        
        curTime = time.time()
        
        timeDiff = curTime-sendTime
        
        lock.acquire()
        timeout_mp[seq] = 0 if timeDiff <= TIMEOUT else 1
        lock.release()

        info = f"{addr} seq = {seq}, {timeDiff:6.3}s {'timeout' if timeDiff > TIMEOUT else ''}"
        print(info)

def quit(signum, frame):
    endinfo = f"---------------statistics---------------\n"
    lock.acquire()
    loss, total = 0, len(timeout_mp)
    for seq in timeout_mp:
        if timeout_mp[seq] == 1:
            loss += 1
    endinfo += f"{total} packets transmitted, {total-loss} packets receive, {int(100*loss/total)}% packet loss"
    print(endinfo)
    lock.release()
    os._exit(1)

def main():
    parser = argparse.ArgumentParser(
        prog="ping",
        description="Send ICMP ECHO_REQUEST packets to network hosts."
    )
    parser.add_argument('host', help="target host ip address", type=str, default='localhost')

    args = parser.parse_args()
    # if not checkIp(args.host):
    #     print('invalid ip format!')
    #     return

    signal.signal(signal.SIGINT, quit)
    signal.signal(signal.SIGTERM, quit)

    sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP)
    ident = os.getpid()

    send_thread = threading.Thread(target=send, args=(sock, args.host, ident%65536))
    send_thread.daemon = True
    send_thread.start()

    recv(sock)
    

main()