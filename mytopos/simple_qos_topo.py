from mininet.topo import Topo

class MyTopo( Topo): 
	"Simple topology example."
	def __init__( self ): 
		"Create custom topo."
		# Initialize topology 

		Topo.__init__( self )
		# Add hosts and switches 
		h1 = self.addHost( 'h1' , ip='10.0.1.100/16' ) 
		h2 = self.addHost( 'h2' , ip='10.0.2.100/16') 
		h3 = self.addHost( 'h3' , ip='10.0.3.100/16') 
		h4 = self.addHost( 'h4' , ip='10.0.4.100/16') 
		s1 = self.addSwitch( 's1' ) 
		s2 = self.addSwitch( 's2' )
	
		# Add links 
	
		self.addLink( h1, s1 ) 
		self.addLink( h2, s1 ) 
		self.addLink( h3, s1 ) 
		self.addLink( s1, s2 ) 
		self.addLink( s2, h4 )

topos= { 'mytopo': ( lambda: MyTopo() ) }
