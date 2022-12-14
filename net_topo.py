from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from functools import partial

class MyTopo( Topo ):
    "Simple topology 3 host as server, 1 switch, and 1 host as client."
    def addSwitch( self, name, **opts ):
        kwargs = { 'protocols' : 'OpenFlow13'}
        kwargs.update( opts )
        return super(MyTopo, self).addSwitch( name, **kwargs )

    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        server1 = self.addHost( 'h1' )
        server2 = self.addHost( 'h2' )
        server3 = self.addHost( 'h3' )
        client1 = self.addHost( 'h4' )
        switch1 = self.addSwitch( 's1' )

        # Add links
        self.addLink( client1, switch1 )
        self.addLink( server1, switch1 )
        self.addLink( server2, switch1 )
        self.addLink( server3, switch1 )

def run():
    "The Topology for Server - Round Robin LoadBalancing"
    topo = MyTopo()
    net = Mininet( topo=topo, controller=RemoteController, autoSetMacs=True, autoStaticArp=True, waitConnected=True )
    
    info("***Disabling IPv6***\n")
    for host in net.hosts:
        #print("disable ipv6 in", host)
        host.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    
    for sw in net.switches:
        #print("disable ipv6 in", sw)
        sw.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")

    info("***Running Web Servers***\n")
    for web in ["h1", "h2", "h3"]:
        info("Web Server running in", web, net[web].cmd("python -m http.server 80 &"))

    info("\n************************\n")
    net.start()
    CLI.do_sh('ovs-vsctl', 'ovs-vsctl -- --id=@ft create Flow_Table flow_limit=50 overflow_policy=refuse -- set Bridge s1 flow_tables=0=@ft')
    info("***Flow Table 0 capacity is set to 50 rules***\n")
    net.pingAll()
    info("\n************************\n")
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    run()
