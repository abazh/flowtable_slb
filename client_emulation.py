import random
import os
import time
import subprocess

# mengkonfigurasi kapasitas flow table = 50

#try:
#    os.system("ovs-vsctl -- --id=@ft create Flow_Table flow_limit=50 overflow_policy=refuse -- set Bridge s1 flow_tables=0=@ft")
#except:
#    print("Gagal set kapasitas Flow Table = 50 flow")
#else:
#    print("Berhasil set kapasitas Flow Table = 50 flow")

# membuat 100 http-request dengan interval 0.5 detik ke server load-balancer http://10.0.0.100 

count = 1
for i in range(1, 101):
    acak = random.randint(6, 25)
    ip = "10.0.0." + str(acak)
    os.system("ifconfig h4-eth0 " + ip)
    time.sleep(0.5)
    output=subprocess.check_output("httping -G http://10.0.0.100 -c1 -m", shell=True)
    print("http-request ke-", count, " dari IP: ", ip, " RTT(ms): ", str(output.decode('utf8','strict')).strip())
    count += 1
