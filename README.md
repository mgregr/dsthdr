dsthdr
======
dsthdr is a kernel module, which adds empty IPv6 Destination Options extension header to all outgoing TCP packets.
The prepending of extension headers is useful when you want to test if a firewall or ACL is working properly.
Some firewalls or vendors do have problems to parse IPv6 extension headers, thus it is able to avoid the
ACL.
