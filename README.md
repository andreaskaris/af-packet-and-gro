Lab setup instructions

Spawn 2 virtual machines with 2 interfaces each. eth0 shall be on the libvirt default virtual network, and eth1 shall be on an isolated network reserved for these 2 instances.

Setup instructions for the left VM:
```
systemctl stop nftables
systemctl stop firewalld
nft flush ruleset
subscription-manager repos --enable=fast-datapath-for-rhel-9-x86_64-rpms
yum install openvswitch3.1 -y
systemctl enable --now openvswitch

nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.123.10/24
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int geneve0 -- set interface geneve0 type=geneve options:remote_ip=192.168.123.11
ip netns add blue
ip link add name veth0 type veth peer name blue0
ovs-vsctl add-port br-int veth0
ip link set dev veth0 up
ip link set dev blue0 netns blue
ip netns exec blue set dev lo up
ip netns exec blue ip link set dev blue0 up
ip netns exec blue ip a a dev blue0 192.168.125.10/24
ip netns exec blue ip link set dev blue0 mtu 1400
ip netns exec blue ip link add tap0 type gretap local 192.168.125.10 remote 192.168.125.11 ikey 0.0.0.1 okey 0.0.0.1
ip netns exec blue ip a a dev tap0 192.168.126.10/24
ip netns exec blue ip link set dev tap0 up
ip netns exec blue ip link set dev lo up
```

Setup instrutions for the right VM:
```
systemctl stop nftables
systemctl stop firewalld
nft flush ruleset
subscription-manager repos --enable=fast-datapath-for-rhel-9-x86_64-rpms
yum install openvswitch3.1 -y
systemctl enable --now openvswitch

nmcli connection add type ethernet con-name eth1 ifname eth1 ip4 192.168.123.11/24
ovs-vsctl add-br br-int
ovs-vsctl add-port br-int geneve0 -- set interface geneve0 type=geneve options:remote_ip=192.168.123.10
ip netns add blue
ip link add name veth0 type veth peer name blue0
ovs-vsctl add-port br-int veth0
ip link set dev veth0 up
ip link set dev blue0 netns blue
ip netns exec blue set dev lo up
ip netns exec blue ip link set dev blue0 up
ip netns exec blue ip a a dev blue0 192.168.125.11/24
ip netns exec blue ip link set dev blue0 mtu 1400
ip netns exec blue ip link add tap0 type gretap local 192.168.125.11 remote 192.168.125.10 ikey 0.0.0.1 okey 0.0.0.1
ip netns exec blue ip a a dev tap0 192.168.126.11/24
ip netns exec blue ip link set dev tap0 up
ip netns exec blue ip link set dev lo up
```

Now, on right, run:
```
ip netns exec blue nc -k -l 192.168.126.11 8080
```

Open another terminal to right, and run:
```
ip netns exec blue ./send-sip.sh 192.168.126.11 8080 short
```

On left, run either of the following commands:
```
ip netns exec blue ./send-sip.sh 192.168.128.13 8080 short
ip netns exec blue ./send-sip.sh 192.168.128.13 8080 long
```

With GRE enabled on genev_sys_6081, you will see the following for the `long` simulated SIP message:
```
(...)
36:26:db:11:a8:ff -> 96:39:cb:86:71:8a, ethertype: 0x800, len: 3382
    version: 4, header len: 20, ttl: 64, proto: 47, checksum: 0xf7af, src: 192.168.125.10, dest: 192.168.125.11
        gre ethertype: 0x6558
            52:e3:b3:f4:80:74 -> 32:cc:9f:e0:44:f4, ethertype: 0x800, len: 3340
                version: 4, header len: 20, ttl: 64, proto: 6, checksum: 0x782b, src: 192.168.126.10, dest: 192.168.126.11
                    src_port: 60626, dest_port: 8080, sequence: 2000908609, checksum: 0x8a65     # <--- checksum mismatch
                    calculated_checksum: 0xe800   # <--- checksum mismatch
(...)
```
