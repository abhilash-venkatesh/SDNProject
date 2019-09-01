import abhilashlibraries
import threading
def hi(h):
	print "HIII"
print(abhilashlibraries.get_ip())
t1 = threading.Thread(target=hi, args=(1,))
