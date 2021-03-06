#!/usr/bin/python
 
"""
A simple minimal topology script for Mininet.
 
Based in part on examples in the [Introduction to Mininet] page on the Mininet's
project wiki.
 
[Introduction to Mininet]: https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#apilevels
 
"""
 
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.node import RemoteController, OVSSwitch
 
class MinimalTopo( Topo ):
    "Minimal topology with a single switch and two hosts"
 
    def build( self ):
        # Create hosts.
        h1 = self.addHost( 'h1', ip = '10.0.0.1', mac = '00:00:00:00:00:01')
        h2 = self.addHost( 'h2', ip = '10.0.0.2', mac = '00:00:00:00:00:02')
        h3 = self.addHost( 'h3', ip = '10.0.0.3', mac = '00:00:00:00:00:03')
        h4 = self.addHost( 'h4', ip = '10.0.0.4', mac = '00:00:00:00:00:04')

        # Host that will simulate outside connections and will be only connected to the rootSwitch
        h5 = self.addHost( 'h5', ip = '10.0.0.5', mac = '00:00:00:00:00:05')
        
        # Create a switch
        s1 = self.addSwitch( 's1' )
        s2 = self.addSwitch( 's2' )
        s3 = self.addSwitch( 's3' )
        s4 = self.addSwitch( 's4' )

        # Links between the rootSwitch(s1) and other switches
        self.addLink( s1, s2 )
        self.addLink( s1, s3 )
        self.addLink( s1, s4 )
        
        # Add links between the switch and each host
        self.addLink( s2, h1 )
        self.addLink( s2, h2 )
        self.addLink( s3, h3 )
        self.addLink( s3, h4 )

        # Add link between internet and the rootSwitch
        self.addLink( s4, h5 )
 
def runMinimalTopo():
    "Bootstrap a Mininet network using the Minimal Topology"
 
    # Create an instance of our topology
    topo = MinimalTopo()
 
    # Create a network based on the topology using OVS and controlled by
    # a remote controller.
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController( name, ip='127.0.0.1' ),
        switch=OVSSwitch,
        autoSetMacs=True )
 
    # Actually start the network
    net.start()
 
    # Drop the user in to a CLI so user can run commands.
    CLI( net )
 
    # After the user exits the CLI, shutdown the network.
    net.stop()
 
if __name__ == '__main__':
    # This runs if this file is executed directly
    setLogLevel( 'info' )
    runMinimalTopo()
 
# Allows the file to be imported using `mn --custom <filename> --topo minimal`
topos = {
    'minimal': MinimalTopo
}
