# arpspoofmod

	File name: arpspoofmod.c
	Author: lngost
    
    Description:
        Written by c with libpcap and pthread.
        May need -lpcap and -lpthread CFLAGS to compile.
    
    Work flow:
        * Send broadcast arp request packets to get 
          mac addresses of target and host.
        * Keep sending arp reply packets to poison.
        * Re-arping victims after ^c pressed and quit.
    
    Compile example:
        OSX: clang -std=gnu99 -lpcap -o arpspoofmod
        Linux: gcc -std=gnu99 -lpcap -lpthread -o arpspoofmod
        
-------------

	NAME
		arpspoofmod - intercept packets on a switched LAN, another 
		implementation of Dug Song's arpspoof tool.

	SYNOPSIS
    	arpspoofmod -i interface -t target [-r] host

	DESCRIPTION
    	arpspoofmod is another implementation of Dug Song's arpspoof tool, 
    	it does nearly the same behaviour with minor different.
    
    	arpspoofmod redirects packets from a target host on the LAN intended 
    	for another host on the LAN by forging ARP replies.
    
    	Kernel IP forwarding (or a userland program which accomplishes the same) 
    	must be turned on ahead of time.
    
    	The reasons for this program is written:
    	(1) Practice purpose
    	(2) The Dug Song's arpspoof is a well-known tool that can be found on 
            many platforms. However, some of the implementations may not act 
            as it claims due to modification of the source. For example, 
            it will only work on remote mode even without -r option provided, 
            which makes you exposed to the gateway. Another example is that 
            it sends broadcast arp replies even a non-broadcast target ip is 
            specified, which really makes a mess.

	OPTIONS
	    -i interface
	        Specify the interface to use.
	        (An interface must be specified.)
	    
	    -t target
	        Specify a particular host to ARP poison.
	        (A target must be specified.)
	        
	    -r
	        remote mode.
	        Posion both hosts (host and target) to capture traffic in both
	        directions. (Only valid in conjunction with -t)
	        If not specified, arpspoofmod will run on oneway mode, which 
	        only poisons target to capture traffic from target to host.
	        
	    host
	        Specify the host you wish to intercept packets for.
	        (Usually the gateway.)
	        (A host must be specified.)

	EXAMPLE
	    Let's say a target is at 192.168.1.5, and the gateway is at 192.168.1.1
	    arpspoofmod -i eth0 -t 192.168.1.5 192.168.1.1
	    
	PRIVILEGES
	    arpspoofmod may need root privileges to send packets on Linux.
	    arpspoofmod may NOT require any special privileges to send packets on OSX.
	    

## Copyright

Copyright 2015 lngost

See <https://github.com/lngost>



## License
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


