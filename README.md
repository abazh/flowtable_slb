# DYNAMIC FLOW REMOVAL UNTUK MENCEGAH FLOW TABLE OVERFLOW 
Penerapan dynamic flow removal diterapkan pada studi kasus aplikasi server load balancing dalam Ryu framework untuk mencegah terjadinya flow table overflow. 

## Menjalankan controller pada Terminal console 1:
> `ryu-manager flowtable_lb.py`
- Perintah ini akan mengeksekusi aplikasi server load balancing (virtual IP: 10.0.0.100) dengan algoritme round-robin pada controller Ryu, dimana pada program ini juga diterapkan monitoring jumlah rincian flow dalam flow table 0 setiap 5 detik, lalu melakukan pengurutan rincian flow berdasarkan durasi, jumlah paket, dan jumlah bytes. Selanjutnya ketika flow table mendekati batas kapasitasnya (dalam hal ini 50 rules), maka rincian flow paling lama akan dihapus untuk memberikan ruang bagi rincian flow baru.

## Menjalankan mininet dengan custom topologi pada Terminal console 2: 
> `sudo python net_topo.py`
- Perintah ini akan menjalankan mininet dengan topologi sederhana 3 server (h1, h2, h3), 1 switch (s1), dan 1 client (h4). Selain itu, juga menjalankan HTTP server pada setiap server dan melakukan set flow table max entries = 50 flow rule pada switch s1

## Menjalankan client emulation pada mininet console:
> mininet> `h4 python client_emulation.py`
- Untuk memicu http-request jamak (100 request) dengan IP acak program dengan interval 0.5 detik dengan httping ke virtual IP 10.0.0.100 (load balancer).
