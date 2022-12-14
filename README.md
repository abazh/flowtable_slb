Setelah melakukan cloning dari repository ini, kemudian jalankan perinta berikut pada 2 terminal console di Linux Ubuntu dengan Mininet dan RYU telah diinstall

#Menjalankan controller pada Terminal console 1:
ryu-manager flowtable_lb.py

#Menjalankan topologi pada Terminal console 2: 
sudo python net_topo.py

#Menjalankan client emulation pada mininet console:
mininet> h4 python client_emulation.py
