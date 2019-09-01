from mininet.topo import Topo

class MyTopo( Topo ):
	
	def __init__(self):

		Topo.__init__(self)

		#Add switch
		switchOne = self.addSwitch('s1')
		#switchTwo = self.addSwitch('s2')

		#Add hosts
		firstHost = self.addHost('h1', ip='10.0.1.100/24', defaultRoute='via 10.0.1.1')
		secondHost = self.addHost('h2', ip='10.0.2.100/24', defaultRoute='via 10.0.2.1')
		thirdHost = self.addHost('h3', ip='10.0.3.100/24', defaultRoute='via 10.0.3.1')
		fourthHost = self.addHost('h4', ip='10.0.4.100/24', defaultRoute='via 10.0.4.1')

		#Add links
		self.addLink (switchOne, firstHost)
		self.addLink (switchOne, secondHost)
		self.addLink (switchOne, thirdHost)
		self.addLink (switchOne, fourthHost)
		#self.addLink (switchOne, switchTwo)
		#self.addLink (switchTwo, fourthHost)



topos = {'mytopo' : (lambda: MyTopo())}
