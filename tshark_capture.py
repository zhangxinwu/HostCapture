import os
import sys

import pyshark
import requests
import signal
import time

tshark_path = "D:\\Program Files\\Wireshark\\tshark.exe"

ip_host = dict()
ip_port = dict()
ip_size = dict()
ip_info = dict()


def gethost(ip):
    if ip in ip_host:
        return " | ".join(ip_host[ip].keys())
    return ""


def getinfo(ip):
    if ip in ip_info:
        return ip_info[ip]

def getcountry():
    u = "http://ip-api.com/batch"
    ips = []
    for k in ip_port:
        if k not in ip_info:
            ips.append(k)
    for i in range(0, len(ips), 10):
        lp = ips[i:min(i+10, len(ips))]
        j = i
        try:
            res = requests.post(u, json=lp)
            print(lp)
            print(res)
            if res.status_code == 200:
                jr = res.json()
                for j in jr:
                    ret = "unknown"
                    if j["status"] == "success":
                        ret = j["country"]
                    if j["status"] == "fail":
                        ret = j["message"]
                    if ret == "":
                        ret = "unknown"
                    ip_info[j["query"]] = ret
        except Exception:
            pass


def gettime():
    return time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(int(time.time())))


isBreak = False
isLock = False


def output():
    print("--------out start--------")
    fnm = "{}.csv".format(gettime())
    print("out file: ", fnm)
    for _ in range(3):
        getcountry()
    print("get country info success.")
    with open(fnm, "w") as f:
        f.write("ip,host,port,size,country\n")
        for ip in ip_port:
            l = ",".join([ip, gethost(ip), "|".join(ip_port[ip].keys()), str(ip_size[ip]), getinfo(ip)])
            print(l)
            f.write(l + "\n")
    print("--------out finish--------")


def handlerInt(signum, frame):
    global isBreak
    isBreak = True
    # output()


def handlerBreak(signum, frame):
    global isLock
    global ip_port, ip_size
    isLock = True
    output()
    ip_port = dict()
    ip_size = dict()
    isLock = False


def find_tshark():
    global tshark_path
    if os.path.exists(tshark_path):
        return
    p = os.getenv("PATH")
    pd = [k for k in p.split(":" if ":" in p else ";")]
    for d in pd:
        pp = os.path.join(d, "tshark.exe")
        if os.path.exists(pp):
            tshark_path = pp
            break
        pp = os.path.join(d, "tshark")
        if os.path.exists(pp):
            tshark_path = pp
            break


def main():
    global isBreak
    find_tshark()
    signal.signal(signal.SIGINT, handlerInt)
    signal.signal(signal.SIGBREAK, handlerBreak)

    if len(sys.argv) > 1:
        capture = pyshark.FileCapture(sys.argv[1], tshark_path=tshark_path)
        isBreak = True
    else:
        os.system("\"" + tshark_path + "\" -D")
        inft = input("select interface: ")
        capture = pyshark.LiveCapture(interface=inft, tshark_path=tshark_path, output_file="out.pcapng")
        print("start...\n Ctrl+Break output & clear\n Ctrl+C stop")
    while True:
        if not isLock:
            for pac in capture:
                ipv = ""
                for la in pac.layers:
                    if la.layer_name.startswith("ip"):
                        ipv = la.dst
                        print(pac.sniff_time, "\t", (la.src + " " * 15)[:17], " --> ", la.dst)
                        if ipv not in ip_size:
                            ip_size[ipv] = 0
                        ip_size[ipv] += int(pac.length)
                    if la.layer_name in ["tcp", "udp"]:
                        if ipv not in ip_port:
                            ip_port[ipv] = dict()
                        ip_port[ipv][la.dstport] = 0
                    if la.layer_name == "dns" and hasattr(la, "resp_name"):
                        try:
                            if hasattr(la, "a"):
                                if la.a not in ip_host:
                                    ip_host[la.a] = dict()
                                ip_host[la.a][la.qry_name] = 0
                        except Exception:
                            pass
        if isBreak:
            break
    output()


if __name__ == '__main__':
    main()
