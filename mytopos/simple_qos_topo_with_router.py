from mininet.topo import Topo

class MyTopo( Topo): 
	"Simple topology example."
	def __init__( self ): 
		"Create custom topo."
		# Initialize topology 

		Topo.__init__( self )
		# Add hosts and switches 
		h1 = self.addHost( 'h1' , ip='10.0.1.100/24' , defaultRoute='via 10.0.1.1') 
		h2 = self.addHost( 'h2' , ip='10.0.1.101/24' , defaultRoute='via 10.0.1.1') 
		h3 = self.addHost( 'h3' , ip='10.0.1.102/24' , defaultRoute='via 10.0.1.1') 
		h4 = self.addHost( 'h4' , ip='10.0.2.100/24' , defaultRoute='via 10.0.2.1') 
		s1 = self.addSwitch( 's1' ) #Router
		s2 = self.addSwitch( 's2' , ip='10.0.2.254/24' , defaultRoute='via 10.0.2.1') #Right Switch 
		s3 = self.addSwitch( 's3' , ip='10.0.1.254/24' , defaultRoute='via 10.0.1.1') #Left Switch
		# Add links 
	
		self.addLink( h1, s3) 
		self.addLink( h2, s3 ) 
		self.addLink( h3, s3 ) 
		self.addLink( s3, s1 ) 
		self.addLink( s1, s2 )
		self.addLink( s2, h4 )

topos= { 'mytopo': ( lambda: MyTopo() ) }
