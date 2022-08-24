#include<mysql.h>
#include<pcap.h>
#include<stdlib.h>
#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<time.h>
#include<string.h>
#include<netinet/in.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type;		    /* IP ARP RARP etc */
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct blocked_ip_list {
	char blocked_ip[100];
};
/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	u_char th_flags;
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

void fin_pcap_error(char *err_str,char *errbuf);
void fin_sql_error(MYSQL *con);
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet); 
void send_to_db(char *ip_src_addr,char *ip_dst_addr,int tcp_src_port,int tcp_dst_port );

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14
u_int size_ip;
u_int size_tcp;


/* MYSQL */
MYSQL_RES *result = NULL; 	
MYSQL mysql;
MYSQL_ROW row;
MYSQL *conPtr = NULL;

const struct sniff_ethernet *ethernet;   /* The ethernet header */
const struct sniff_ip *ip; 		 /* The IP header */
const struct sniff_tcp *tcp; 		 /* The TCP header */
const char *payload;			 /* Packet payload */

int main(int argc,char *argv[])	
{
	int num_fields,i;
	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;     /* The actual packet */

#define def_host_name   NULL     /* host to connect to (default = localhost) */
#define def_user_name   "root"   /* user name (default = your login name) "*/
#define def_password    "ubuntu" /* password (default = none) */
#define def_db_name     NULL     /* dtabases to use (default = none) */
#define def_port_num    0        /* use default port */
#define def_socket_name NULL     /* use default socket name */

	/* init MYSQL & connect */
	mysql_init(&mysql);
	conPtr = mysql_real_connect(&mysql,
			def_host_name,
			def_user_name,
			def_password,
			def_db_name ,
			def_port_num ,
			def_socket_name,
			0			);
	if ( conPtr == NULL ) 	    fin_sql_error("\n** Login failed **\n");
	puts("\n** Login success **");
	printf("MySQL Version - %s \n",mysql_get_client_info());	
	printf("Listening... ");

	/*Define dev & set pcap*/
	dev = pcap_lookupdev(errbuf);
	if ( dev == NULL)
		fin_pcap_error("Failed to default device : ",errbuf);
	    
	if ( pcap_lookupnet(dev,&net,&mask,errbuf) == -1){
		fin_pcap_error("Failed to get net&mask for device : ",dev);
		net = mask = 0;
	}
	handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if ( handle == NULL)
		fin_pcap_error("Failed to open device : ",dev);
		
	if ( pcap_compile(handle,&fp,filter_exp,0,net) == -1)
		fin_pcap_error("Failed to parse filter : ",filter_exp);
	
	if ( pcap_setfilter(handle,&fp) == -1) 
		fin_pcap_error("Failed to set filter : ",filter_exp);
	
	if ( pcap_loop(handle,2,got_packet,NULL) != 0) 
		fprintf(stderr,"Failded to call pcaploop packets");
		
	result = mysql_store_result(conPtr);
	if( result == NULL)	
		fin_sql_error(conPtr);

	num_fields = mysql_num_fields(result);
	row = mysql_fetch_row(result);
//	printf("%s",row[0]);	
	while(row = mysql_fetch_row(result)){	
		for( i = 0; i < num_fields ; i++)
			printf("[%s]  ",row[i] ? row[i] : "NULL");
		puts("");
	}
	mysql_free_result(result);
	mysql_close(conPtr);
	pcap_close(handle);

	return 0;
}//End of main
void fin_sql_error(MYSQL *conPtr)
{	
	fprintf(stderr,"[ SQL ERROR %s ]\n",mysql_error(conPtr));
	mysql_close(conPtr);
	exit(1);	
}
void fin_pcap_error(char *err_str,char *errbuf)
{
	fprintf(stderr,"[ PCAP ERROR ]%s %s\n",err_str,errbuf);
	exit(1);
}
void send_to_db(char *ip_src_addr,char *ip_dst_addr,int tcp_src_port,int tcp_dst_port )
{
	char *sql_query = NULL;
	sql_query = (char*)malloc(sizeof(char)*10000);
	memset(sql_query,0,sizeof(char)*10000);
        mysql_select_db(conPtr,"pcap_db");
	mysql_query(conPtr,"SELECT *FROM hostInfo");

/**	sprintf(sql_query,"INSERT INTO hostInfo VALUES('LocalHost','%s','%s','%d','%d')",ip_src_addr,ip_dst_addr,tcp_src_port,tcp_dst_port);

	if ( mysql_query(conPtr,sql_query) != 0){
 		fin_sql_error(conPtr);
		exit(1);
	} 
	printf("test2");
	sprintf(char *str,const char*format,..)  */
		
	free(sql_query);	
}
void got_packet(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{	
	struct tm *ptm = localtime(&header->ts.tv_sec);
	char ip_src_addr[21] = {};
	char ip_dst_addr[20] = {};
	int  tcp_src_port = 0;
	int  tcp_dst_port = 0;
	
	ethernet = (struct sniff_ethernet*)(packet);
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;

	/** packet time & length */
	printf("Packet Time : %4d-%02d-%02d  %02d:%02d:%02d\n",
		ptm->tm_year + 1900,
		ptm->tm_mon + 1,
		ptm->tm_mday,
	        ptm->tm_hour,
        	ptm->tm_min,
       	        ptm->tm_sec);
	printf("Packet Lenght :%d\n",header->len);
	size_ip = IP_HL(ip) * 4;
	
	if ( size_ip < 20 ) {
		printf("**  Invaild IP header lenght: %u bytes  **\n",size_ip);
		return;
	}
	/** ip address */
	strcpy(ip_src_addr, inet_ntoa(ip->ip_src));
	strcpy(ip_dst_addr, inet_ntoa(ip->ip_dst));
	printf("IP Source : %s \n",ip_src_addr);
	printf("IP Destination : %s \n",ip_dst_addr);
	

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	size_tcp = 20;
	if ( size_tcp < 20 ) {
		printf("**  Invailed TCP header lenght: %u bytes  **\n",size_tcp);
		return;
	}
	/** tcp port */
	tcp_src_port = ntohs(tcp->th_sport);
	tcp_dst_port = ntohs(tcp->th_dport);
        printf("Source Port : %d\n",tcp_src_port);	  
	printf("Destination Port : %d\n",tcp_dst_port);
	
	/** payload address */
	payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	send_to_db(ip_src_addr, ip_dst_addr, tcp_src_port, tcp_dst_port);
	printf("DEBUG - payload address : %p.\n\n",payload);	
}






