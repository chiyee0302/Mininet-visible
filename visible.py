from mininet.net import Mininet
from flask import Flask, render_template, request, redirect, url_for,jsonify
from mininet.topo import Topo
from mininet.node import Host
from scapy.all import *
from scapy.layers.inet import *
from scapy import *
import random



app = Flask(__name__)

class ryu_topo(Topo):
    def __init__(self):
        Topo.__init__(self)
        self.addSwitch("s1")
        self.addSwitch("s2")
        self.addHost("h1")
        self.addHost("h2")
        self.addHost("h3")
        self.addHost("h4")
        self.addLink("s1", "h1")
        self.addLink("s1", "h2")
        self.addLink("s2", "h3")
        self.addLink("s2", "h4")
        self.addLink("s1", "s2")

# 在全局范围内声明 net
net = Mininet(topo=ryu_topo())












class CountMinSketch:
    def __init__(self, width, depth):
        self.width = width  # 宽度
        self.depth = depth  # 深度
        self.table = [[0] * width for _ in range(depth)]  # 初始化表格

    def update(self, key):
        for i in range(self.depth):
            hash_val = int(hashlib.sha256(f"{key}{i}".encode()).hexdigest(), 16) % self.width
            self.table[i][hash_val] += 1

    def query(self, key):
        min_count = float('inf')
        for i in range(self.depth):
            hash_val = int(hashlib.sha256(f"{key}{i}".encode()).hexdigest(), 16) % self.width
            min_count = min(min_count, self.table[i][hash_val])
        return min_count

# 数据流
data_stream = [
    #("source_ip_1", "dest_ip_1", "source_port_1", "dest_port_1", "protocol_1"),
    #("source_ip_2", "dest_ip_2", "source_port_2", "dest_port_2", "protocol_2"),
    # ... 更多流量数据
]

def process_pcap_file(filename):
    pkts = rdpcap(filename)
    for pkt in pkts:
        # 提取源IP、目标IP、源端口、目标端口、协议等信息，创建五元组
        if IP in pkt and TCP in pkt:
            five_tuple = (
                pkt[IP].src,
                pkt[IP].dst,
                str(pkt[TCP].sport),
                str(pkt[TCP].dport),
                "TCP"  # 这里假设都是 TCP 协议，如果有其他协议，需要相应修改
            )
            data_stream.append(five_tuple)

# process_pcap_file('sdn.scap')


# 添加链路
def add_link(node1,node2):
    net.addLink(node1,node2)

# 添加主机
def add_host(new_host_name, new_host_ip, switch_name):
    host = net.addHost(new_host_name)
    add_link(host,switch_name)

    # 设置主机的 IP 地址
    host.intf(host.name + '-eth0').setIP(new_host_ip)

# 添加交换机
def add_switch(switch_name):
    net.addSwitch(switch_name)
    
# 删除链路
def del_link(link):
    host1 = link.intf1.node
    host2 = link.intf2.node
    net.delLink(link)  # 从网络中删除链路
    if isinstance(host1, Host):
        host1.intf(host1.name + '-eth0').setIP("0.0.0.0/0")
    if isinstance(host2, Host):
        host2.intf(host2.name + '-eth0').setIP("0.0.0.0/0")

    

# 删除主机
def del_host(del_host_name):
    # 删除所连接的链路
    for link in net.links:
        if (link.intf1.node.name == del_host_name) or (link.intf2.node.name == del_host_name):
            del_link(link)
    net.delHost(net[del_host_name])

# 删除交换机
def del_switch(del_switch_name):
    # 删除所连接的链路
    for link in net.links:
        if (link.intf1.node.name == del_switch_name) or (link.intf2.node.name == del_switch_name):
            del_link(link)
    net.delSwitch(net[del_switch_name])




@app.route('/')
def index():
    # 获取拓扑信息
    hosts = net.hosts
    switches = net.switches


    print(hosts)


    # 将拓扑信息转换为适合 HTML 格式的数据
    topology_data = {
        "hosts": [(host.name, host.IP(), host.MAC()) for host in hosts],
        "switches": [switch.name for switch in switches],
        "links": [(link.intf1.node.name, link.intf2.node.name) for link in net.links]
    }

    return render_template('sdn_item.html', topology_data=topology_data)

@app.route('/add_host', methods=['POST'])
def add_host_route():
    new_host_name = request.form['new_host_name']
    new_host_ip = request.form['new_host_ip']
    switch_name = request.form['switch_name']
    add_host(new_host_name, new_host_ip, switch_name)
    return redirect(url_for('index'))


@app.route('/add_switch', methods=['POST'])
def add_switch_route():
    switch_name = request.form['new_switch_name']
    add_switch(switch_name)
    return redirect(url_for('index'))


@app.route('/add_link', methods=['POST'])
def add_link_route():
    node1 = request.form['node1']
    node2 = request.form['node2']
    add_link(node1,node2)
    return redirect(url_for('index'))

@app.route('/del_host', methods=['POST'])
def del_host_route():
    del_host_name = request.form['del_host_name']
    del_host(del_host_name)
    return redirect(url_for('index'))
    
@app.route('/del_switch', methods=['POST'])
def del_switch_route():
    del_switch_name = request.form['del_switch_name']
    del_switch(del_switch_name)
    return redirect(url_for('index'))

@app.route('/del_link', methods=['POST'])
def del_link_route():
    node1 = request.form['node1']
    node2 = request.form['node2']
    for link in net.links:
        if (link.intf1.node.name == node1 and link.intf2.node.name == node2) or \
           (link.intf1.node.name == node2 and link.intf2.node.name == node1):
           del_link(link)
    return redirect(url_for('index'))





if __name__ == '__main__':
    
    app.run(debug=True,port=5001, use_reloader=False)  # 关闭 Flask 的自动重载功能
