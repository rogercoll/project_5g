#Instructions

1- Install suricata

2- Install influxdb, telegraf and grafana

3- Copy telegraf/telegraf.conf into /etc/telegraf/telegraf.conf

4- Copy suricata/suricata.yaml and suricata/rules/\* into /etc/suricata

5- Install ryu controller

6- Copy the file simple_switch_suricata.py into your ryu/ryu/app directory


7- Run the following commands to test suricata and ryu


```
sudo ip link add name s1-suricata type dummy
sudo ip link set s1-suricata up


#Run mininet
sudo mn --topo single,2 --mac --controller remote --switch ovsk

#Add port to switch
sudo ovs-vsctl add-port s1 s1-suricata
sudo ovs-ofctl show s1
$Find the number of the new port and update self.snort_port
variable in simple_switch_suricata.py

#Run RYU
sudo ryu-manager --verbose ryu/ryu/app/simple_switch_suricata.py
```
