#include <netinet/in.h>
#include <map>
#include <cstdio>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <iterator>
#include <algorithm>
#include <net/ethernet.h>
#include <ifaddrs.h>
#include <cstring>
#include <cassert>
#include "packet.h"
#include "connection.h"
#include "ConnList.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/stat.h>
#include <iostream>

#define HASHKEYSIZE 92
int promisc =1;

char errbuf[PCAP_ERRBUF_SIZE];
using namespace std;
std::map<std::string, unsigned long> conninode;
static time_t last_refresh_time = 0;
time_t refreshdelay = 1;
timeval curtime;
/* the amount of time after the last packet was received
 * after which a connection is removed */
#define CONNTIMEOUT 50
#define PERIOD 5
typedef struct pcap_pkthdr dp_header;
typedef int (*dp_callback)(u_char *, const dp_header *, const u_char *);

/**
*DPARGS
**/
struct dpargs {
  const char *device;
  int sa_family;
  in_addr ip_src;
  in_addr ip_dst;
  in6_addr ip6_src;
  in6_addr ip6_dst;
};




/**
*LINE FOR DISPLAY
**/

class Line {
public:
  Line(const char *name, const char *cmdline, double n_recv_value,
       double n_sent_value, pid_t pid, uid_t uid, const char *n_devicename) {
    assert(pid >= 0);
   // assert(pid <= PID_MAX);
    m_name = name;
    m_cmdline = cmdline;
    sent_value = n_sent_value;
    recv_value = n_recv_value;
    devicename = n_devicename;
    m_pid = pid;
    m_uid = uid;
    assert(m_pid >= 0);
  }

  void show(int row, unsigned int proglen);
  void log();

  double sent_value;
  double recv_value;

private:
  const char *m_name;
  const char *m_cmdline;
  const char *devicename;
  pid_t m_pid;
  uid_t m_uid;
};

void Line::log() {
  std::cout << "m_pid :"<<m_pid<<"\tm_uid:"<< m_uid << "\tsent_value:" << sent_value << "\trecv value:" << recv_value <<"\tname of process:"<<m_name<<std::endl;
}

void show_trace(Line *lines[], int nproc) {
  
  /* print them */
  for (int i = 0; i < nproc; i++) {
    lines[i]->log();
    delete lines[i];
  }

  /* print the 'unknown' connections, for debugging */
  /*ConnList *curr_unknownconn = unknowntcp->connections;
  while (curr_unknownconn != NULL) {
    std::cout << "Unknown connection: "
              << curr_unknownconn->getVal()->refpacket->gethashstring()
              << std::endl;

    curr_unknownconn = curr_unknownconn->getNext();
  }*/
}

/*int GreatestFirst(const void *ma, const void *mb) {
  Line **pa = (Line **)ma;
  Line **pb = (Line **)mb;
  Line *a = *pa;
  Line *b = *pb;
  double aValue;
  if (sortRecv) {
    aValue = a->recv_value;
  } else {
    aValue = a->sent_value;
  }

  double bValue;
  if (sortRecv) {
    bValue = b->recv_value;
  } else {
    bValue = b->sent_value;
  }

  if (aValue > bValue) {
    return -1;
  }
  if (aValue == bValue) {
    return 0;
  }
  return 1;
}*/
/**
**Packet
**/

/**
*Cnnection etc
**/



 

/* Find the connection this packet belongs to */
/* (the calling code may free the packet afterwards) */
//Connection *findConnection(Packet *packet);







/**
*ConnLIst
**/

/**
*PROCESS
**/
class Process {
private:
  const unsigned long inode;
  uid_t uid;
public:
  /* the process makes a copy of the name. the device name needs to be stable.
   */
  char *name;
  char *cmdline;
  const char *devicename;
  int pid;
  u_int64_t sent_by_closed_bytes;
  u_int64_t rcvd_by_closed_bytes;

  ConnList *connections;
  Process(const unsigned long m_inode, const char *m_devicename,
          const char *m_name = NULL, const char *m_cmdline = NULL)
      : inode(m_inode) {
    // std::cout << "ARN: Process created with dev " << m_devicename <<
    // std::endl;
   printf("PROC: Process created at %s  \n",this );
  // printf("device name:%s m_name:%d",m_devicename,m_name); 

    if (m_name == NULL)
      name = NULL;
    else
      name = strdup(m_name);
    std::cout<<"process name:"<<name;

    if (m_cmdline == NULL)
      cmdline = NULL;
    else
      cmdline = strdup(m_cmdline);

    devicename = m_devicename;
    connections = NULL;
    pid = 0;
    uid = 0;
    sent_by_closed_bytes = 0;
    rcvd_by_closed_bytes = 0;
  }
  //void check() { assert(pid >= 0); }

  ~Process() {
    free(name);
    free(cmdline);
    //if (DEBUG)
      //std::cout << "PROC: Process deleted at " << this << std::endl;
  }
  
  int getLastPacket(){
  	int lastpacket = 0;
  ConnList *curconn = connections;
  while (curconn != NULL) {
    assert(curconn != NULL);
    assert(curconn->getVal() != NULL);
    if (curconn->getVal()->getLastPacket() > lastpacket)
      lastpacket = curconn->getVal()->getLastPacket();
    curconn = curconn->getNext();
  }
  return lastpacket;
  }

  void gettotal(u_int64_t *recvd, u_int64_t *sent){
  u_int64_t sum_sent = 0, sum_recv = 0;
  ConnList *curconn = this->connections;
  while (curconn != NULL) {
    Connection *conn = curconn->getVal();
    sum_sent += conn->sumSent;
    sum_recv += conn->sumRecv;
    curconn = curconn->getNext();
  }
  printf("Sum sent: %d",sum_sent);
  printf("Sum recv: %d",sum_recv);
  // std::cout << "Sum recv: " << sum_recv << std::endl;
  *recvd = sum_recv + this->rcvd_by_closed_bytes;
  *sent = sum_sent + this->sent_by_closed_bytes;
}

timeval curtime;
float tokb(u_int64_t bytes) { return ((double)bytes) / 1024; }
float tokbps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / 1024; }

  void getkbps(float *recvd, float *sent){
  u_int64_t sum_sent = 0, sum_recv = 0;

  /* walk though all this process's connections, and sum
   * them up */
  ConnList *curconn = this->connections;
  ConnList *previous = NULL;
  while (curconn != NULL) {
    if (curconn->getVal()->getLastPacket() <= curtime.tv_sec - CONNTIMEOUT) {
      /* capture sent and received totals before deleting */
      this->sent_by_closed_bytes += curconn->getVal()->sumSent;
      this->rcvd_by_closed_bytes += curconn->getVal()->sumRecv;
      /* stalled connection, remove. */
      ConnList *todelete = curconn;
      Connection *conn_todelete = curconn->getVal();
      curconn = curconn->getNext();
      if (todelete == this->connections)
        this->connections = curconn;
      if (previous != NULL)
        previous->setNext(curconn);
      delete (todelete);
      delete (conn_todelete);
    } else {
      u_int64_t sent = 0, recv = 0;
      curconn->getVal()->sumanddel(curtime, &recv, &sent);
      sum_sent += sent;
      sum_recv += recv;
      previous = curconn;
      curconn = curconn->getNext();
    }
  }
  *recvd = tokbps(sum_recv);
  *sent = tokbps(sum_sent);
}

    // no? refresh and check conn/inode table
     
 /* void gettotalmb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  *recvd = tomb(sum_recv);
  *sent = tomb(sum_sent);
}*/
  //void gettotalkb(float *recvd, float *sent);
void gettotalkb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  *recvd = tokb(sum_recv);
  *sent = tokb(sum_sent);
}

  /*void gettotalb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  // std::cout << "Total sent: " << sum_sent << std::endl;
  *sent = sum_sent;
  *recvd = sum_recv;
}

 */
  uid_t getUid() { return uid; }

  void setUid(uid_t m_uid) { uid = m_uid; }

  unsigned long getInode() { return inode; }


};

class ProcList {
public:
  ProcList(Process *m_val, ProcList *m_next) {
    assert(m_val != NULL);
    val = m_val;
    next = m_next;
  }
  int size(){
  int i = 1;

  if (next != NULL)
    i += next->size();

  return i;
}
  Process *getVal() { return val; }
  ProcList *getNext() { return next; }
  ProcList *next;

private:
  Process *val;
};
Process *unknowntcp;
Process *unknownudp;
Process *unknownip;
ProcList *processes;
struct prg_node {
  long inode;
  pid_t pid;
  std::string cmdline;
};
std::map<unsigned long, prg_node *> inodeproc;
struct prg_node *findPID(unsigned long inode) {
  /* we first look in inodeproc */
  struct prg_node *node = inodeproc[inode];

  if (node != NULL) {
    
    return node;
  }


  struct prg_node *retval = inodeproc[inode];
  
    
  
  return retval;
}

Process *findProcess(struct prg_node *node) {
  ProcList *current = processes;
  while (current != NULL) {
    Process *currentproc = current->getVal();
    assert(currentproc != NULL);

    if (node->pid == currentproc->pid)
      return current->getVal();
    current = current->next;
  }
  return NULL;
}

Process *findProcess(unsigned long inode) {
  struct prg_node *node = findPID(inode);

  if (node == NULL)
    return NULL;

  return findProcess(node);
}
Process *getProcess(unsigned long inode, const char *devicename) {
  struct prg_node *node = findPID(inode);

  if (node == NULL) {
    
    return NULL;
  }

  Process *proc = findProcess(node);

  if (proc != NULL)
    return proc;

  // extract program name and command line from data read from cmdline file
  const char *prgname = node->cmdline.c_str();
  const char *cmdline = prgname + strlen(prgname) + 1;

  Process *newproc = new Process(inode, devicename, prgname, cmdline);
  newproc->pid = node->pid;

  char procdir[100];
  sprintf(procdir, "/proc/%d", node->pid);
  struct stat stats;
  int retval = stat(procdir, &stats);

  /* 0 seems a proper default.
   * used in case the PID disappeared while nethogs was running
   * TODO we can store node->uid this while info on the inodes,
   * right? */
  /*
  if (!ROBUST && (retval != 0))
  {
          std::cerr << "Couldn't stat " << procdir << std::endl;
          assert (false);
  }
  */

  if (retval != 0)
    newproc->setUid(0);
  else
    newproc->setUid(stats.st_uid);

  /*if (getpwuid(stats.st_uid) == NULL) {
          std::stderr << "uid for inode
          if (!ROBUST)
                  assert(false);
  }*/
  processes = new ProcList(newproc, processes);
  return newproc;
}


Process *getProcess(Connection *connection, const char *devicename) {
  unsigned long inode = conninode[connection->refpacket->gethashstring()];

  if (inode == 0) {
      /* HACK: the following is a hack for cases where the
       * 'local' addresses aren't properly recognised, as is
       * currently the case for IPv6 */

      /* we reverse the direction of the stream if
       * successful. */
      Packet *reversepacket = connection->refpacket->newInverted();
      inode = conninode[reversepacket->gethashstring()];

      if (inode == 0) {
        delete reversepacket;
        
        unknowntcp->connections =
            new ConnList(connection, unknowntcp->connections);
        return unknowntcp;
      }

      delete connection->refpacket;
      connection->refpacket = reversepacket;
    }

  

  
  Process *proc = NULL;
  if (inode != 0)
    proc = getProcess(inode, devicename);

  if (proc == NULL) {
    proc = new Process(inode, "", connection->refpacket->gethashstring());
    processes = new ProcList(proc, processes);
  }

  proc->connections = new ConnList(connection, proc->connections);
  return proc;
}




void process_init() {
  unknowntcp = new Process(0, "", "unknown TCP");
  // unknownudp = new Process (0, "", "unknown UDP");
  // unknownip = new Process (0, "", "unknown IP");
  processes = new ProcList(unknowntcp, NULL);
  // processes = new ProcList (unknownudp, processes);
  // processes = new ProcList (unknownip, processes);
}

void refreshconninode();

void procclean();

void remove_timed_out_processes();


/**
**Fetching DEVICES
***/


class device {
public:
  device(const char *m_name, device *m_next = NULL) {
    name = m_name;
    next = m_next;
  }
  const char *name;
  device *next;
};



void printDevices(device *dev){
	device *temp=dev;
	
	while(temp->next!=NULL){
		printf("%s\n",temp->name);
		temp=temp->next;
	}
}
bool search(const char *m_name,device *dev){
	device *temp=dev;
	
	while(temp->next!=NULL && temp->name!=NULL){

		if(strcmp(temp->name,m_name)==0)
			return true;
		temp=temp->next;
		
	}
	return false;
}

device *get_devices() {
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    printf("Failed to get interface addresses\n" );
    // perror("getifaddrs");
    return NULL;
  }

  device *devices = NULL;
  int count=0;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
  		if((devices)!=NULL)
  	{	 const char * name=strdup(ifa->ifa_name);
  	if ( search(name,devices))
  		continue;}
        devices = new device(strdup(ifa->ifa_name), devices);

        
  }
  printf("%d",count);

  freeifaddrs(ifaddr);
  return devices;
}
/**
** Pcap LOOKUP
**/
enum dp_packet_type {
  dp_packet_ethernet,
  dp_packet_ppp,
  dp_packet_sll,
  dp_packet_ip,
  dp_packet_ip6,
  dp_packet_tcp,
  dp_packet_udp,
  dp_n_packet_types
};
struct dp_handle {
  pcap_t *pcap_handle;
  dp_callback callback[dp_n_packet_types];
  int linktype;
  u_char *userdata;
  int userdata_size;
};


//int process_ip(u_char *userdata, const dp_header * /* header */,
  /*             const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  struct ip *ip = (struct ip *)m_packet;
  args->sa_family = AF_INET;
  args->ip_src = ip->ip_src;
  args->ip_dst = ip->ip_dst;

  *//* we're not done yet - also parse tcp :) */
//  return false;
//}



void dp_addcb(struct dp_handle *handle, enum dp_packet_type type,
              dp_callback callback) {
  handle->callback[type] = callback;
}


struct dp_handle *dp_fillhandle(pcap_t *phandle) {
  struct dp_handle *retval =
      (struct dp_handle *)malloc(sizeof(struct dp_handle));
  int i;
  retval->pcap_handle = phandle;

  for (i = 0; i < dp_n_packet_types; i++) {
    retval->callback[i] = NULL;
  }

  retval->linktype = pcap_datalink(retval->pcap_handle);

  switch (retval->linktype) {
  case (DLT_EN10MB):
    printf( "Ethernet link detected\n");
    break;
  case (DLT_PPP):
    printf( "PPP link detected\n");
    break;
  case (DLT_LINUX_SLL):
    printf( "Linux Cooked Socket link detected\n");
    break;
  default:
    printf( "No PPP or Ethernet link: %d\n", retval->linktype);
    // TODO maybe error? or 'other' callback?
    break;
  }

  return retval;
}

struct dp_handle *dp_open_live(const char *device, int snaplen, int promisc,
                               int to_ms,  char *errbuf) {
  struct bpf_program fp; // compiled filter program
  bpf_u_int32 maskp; // subnet mask
  bpf_u_int32 netp; // interface IP

  pcap_t *temp = pcap_open_live(device, snaplen, 0, to_ms, errbuf);

  if (temp == NULL) {
  	printf("failed to get a handle for device :%s \n",device);
        return NULL;
    
  }

 
    pcap_lookupnet(device, &netp, &maskp, errbuf);

   

  
printf("handle created");
  return dp_fillhandle(temp);

}
int process_ip(u_char *userdata, const dp_header * /* header */,
               const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  struct ip *ip = (struct ip *)m_packet;
  args->sa_family = AF_INET;
  args->ip_src = ip->ip_src;
  args->ip_dst = ip->ip_dst;

  /* we're not done yet - also parse tcp :) */
  return false;
}


int process_tcp(u_char *userdata, const dp_header *header,
                const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  struct tcphdr *tcp = (struct tcphdr *)m_packet;

  curtime = header->ts;

  /* get info from userdata, then call getPacket */
  Packet *packet;
  switch (args->sa_family) {
  case AF_INET:

    packet = new Packet(args->ip_src, ntohs(tcp->th_sport), args->ip_dst,
                        ntohs(tcp->th_dport), header->len, header->ts);

//    packet = new Packet(args->ip_src, ntohs(tcp->source), args->ip_dst,
//                        ntohs(tcp->dest), header->len, header->ts);
//#endif
    break;
  case AF_INET6:
 
    packet = new Packet(args->ip6_src, ntohs(tcp->th_sport), args->ip6_dst,
                        ntohs(tcp->th_dport), header->len, header->ts);
/*
    packet = new Packet(args->ip6_src, ntohs(tcp->source), args->ip6_dst,
                        ntohs(tcp->dest), header->len, header->ts);*/

    break;
  default:
    printf("error");
    return true;
  }

  Connection *connection = findConnection(packet);

  if (connection != NULL) {
    /* add packet to the connection */
    connection->add(packet);
  } else {
    /* else: unknown connection, create new */
    connection = new Connection(packet);
    getProcess(connection, args->device);
  }
  delete packet;

  /* we're done now. */
  return true;
}

int process_ip6(u_char *userdata, const dp_header * /* header */,
                const u_char *m_packet) {
  struct dpargs *args = (struct dpargs *)userdata;
  const struct ip6_hdr *ip6 = (struct ip6_hdr *)m_packet;
  args->sa_family = AF_INET6;
  args->ip6_src = ip6->ip6_src;
  args->ip6_dst = ip6->ip6_dst;

  /* we're not done yet - also parse tcp :) */
  return false;
}





void dp_parse_tcp(struct dp_handle *handle, const dp_header *header,
                  const u_char *packet) {
  // const struct tcphdr * tcp = (struct tcphdr *) packet;
  // u_char * payload = (u_char *) packet + sizeof (struct tcphdr);

  if (handle->callback[dp_packet_tcp] != NULL) {
    printf("exec\n");
    int done =
        (handle->callback[dp_packet_tcp])(handle->userdata, header, packet);
    if (done)
      return;
  }

  // TODO: maybe `pass on' payload to lower-level protocol parsing
}

void dp_parse_ip(struct dp_handle *handle, const dp_header *header,
                 const u_char *packet) {
  const struct ip *ip = (struct ip *)packet;
 
    printf( "Looking at packet with length %d\n", header->len);
  
  u_char *payload = (u_char *)packet + sizeof(struct ip);

  if (handle->callback[dp_packet_ip] != NULL) {
    int done =
        (handle->callback[dp_packet_ip])(handle->userdata, header, packet);
    if (done)
      return;
  }
  switch (ip->ip_p) {
  case IPPROTO_TCP:
  printf("exec tcp \n");
    dp_parse_tcp(handle, header, payload);
    break;
  default:
    // TODO: maybe support for non-tcp IP packets
    break;
  }
}

void dp_parse_ip6(struct dp_handle *handle, const dp_header *header,
                  const u_char *packet) {
  const struct ip6_hdr *ip6 = (struct ip6_hdr *)packet;
  u_char *payload = (u_char *)packet + sizeof(struct ip6_hdr);

  if (handle->callback[dp_packet_ip6] != NULL) {
    int done =
        (handle->callback[dp_packet_ip6])(handle->userdata, header, packet);
    if (done)
      return;
  }
  switch ((ip6->ip6_ctlun).ip6_un1.ip6_un1_nxt) {
  case IPPROTO_TCP:
    dp_parse_tcp(handle, header, payload);
    break;
  default:
    // TODO: maybe support for non-tcp ipv6 packets
    break;
  }
}




void dp_parse_ethernet(struct dp_handle *handle, const dp_header *header,
                       const u_char *packet) {
  const struct ether_header *ethernet = (struct ether_header *)packet;
  u_char *payload = (u_char *)packet + sizeof(struct ether_header);
  u_int16_t protocol = 0;

  /* call handle if it exists */
 if (handle->callback[dp_packet_ethernet] != NULL) {
    int done = (handle->callback[dp_packet_ethernet])(handle->userdata, header,
                                                    packet);

    /* return if handle decides we're done */
    if (done)
      return;
  }
  printf("call back is null\n");

  /* parse payload */
  protocol = ntohs(ethernet->ether_type);
  printf("protocol:%d\n",protocol);
  switch (protocol) {
  case ETHERTYPE_IP:
    printf("ethertype ip exec");
    dp_parse_ip(handle, header, payload);
    break;
  case ETHERTYPE_IPV6:
    dp_parse_ip6(handle, header, payload);
    break;
  default:
    // TODO: maybe support for other protocols apart from IPv4 and IPv6
    break;
  }
}



void dp_pcap_callback(u_char *u_handle, const struct pcap_pkthdr *header,
                      const u_char *packet) {
  struct dp_handle *handle = (struct dp_handle *)u_handle;
  struct dp_header;

  /* make a copy of the userdata for every packet */
  u_char *userdata_copy = (u_char *)malloc(handle->userdata_size);
  if(userdata_copy!=NULL)
  memcpy(userdata_copy, handle->userdata, handle->userdata_size);
printf("##########PACKET###############\n");
printf("linktype:%d Data:%s\n",handle->linktype,userdata_copy);
//printf("\nlinktype value check:%d",DLT_EN10MB);
  switch (handle->linktype) {
  case (DLT_EN10MB):
    dp_parse_ethernet(handle, header, packet);
    break;
  /*case (DLT_PPP):
    dp_parse_ppp(handle, header, packet);
    break;
  case (DLT_LINUX_SLL):
    dp_parse_linux_cooked(handle, header, packet);
    break;
  */
  //case (DLT_RAW):
  /*case (DLT_NULL):
    // hope for the best
    dp_parse_ip(handle, header, packet);
    break;
  default:
    printf( "Unknown linktype %d", handle->linktype);
    break;
  }*/
  }
  free(userdata_copy);
}



int dp_dispatch(struct dp_handle *handle, int count, u_char *user, int size) {
  handle->userdata = user;
  handle->userdata_size = size;
  printf("hi am here\n");
  return pcap_dispatch(handle->pcap_handle, 5, dp_pcap_callback,
                       (u_char *)handle);
}
/**
*handle to store handles for different devices
**/

class handle {
public:
  handle(dp_handle *m_handle, const char *m_devicename = NULL,
         handle *m_next = NULL) {
    content = m_handle;
    next = m_next;
    devicename = m_devicename;
  }
  dp_handle *content;
  const char *devicename;
  handle *next;
};

void printHandles(handle *handles){
	for(handle * temp=handles;temp !=NULL;temp=temp->next){
		printf("dev name:%s ,\n",temp->devicename);
	}
}


/**
***Connection hash tables after reading from proc file
***/

class local_addr{
private:
	in_addr_t addr;
	struct in6_addr addr6;
	short int sa_family;
public:
	char *string;
	local_addr *next;
	local_addr(in_addr_t m_addr,local_addr *mnext=NULL){
		addr=m_addr;
		next=mnext;
		sa_family=AF_INET6;
		string=(char *)malloc(16);
		inet_ntop(AF_INET6,&m_addr,string,15);

	}
	local_addr(struct in6_addr *m_addr, local_addr *m_next = NULL) {
    addr6 = *m_addr;
    next = m_next;
    sa_family = AF_INET6;
    string = (char *)malloc(64);
    inet_ntop(AF_INET6, &m_addr, string, 63);
  }

bool contains(const struct in6_addr &n_addr);
bool contains(const in_addr_t &n_addr);

};




bool local_addr::contains(const struct in6_addr &n_addr) {
  if (sa_family == AF_INET6) {
    /*
    if (DEBUG) {
            char addy [50];
            std::cerr << "Comparing: ";
            inet_ntop (AF_INET6, &n_addr, addy, 49);
            std::cerr << addy << " and ";
            inet_ntop (AF_INET6, &addr6, addy, 49);
            std::cerr << addy << std::endl;
    }
    */
    // if (addr6.s6_addr == n_addr.s6_addr)
    if (memcmp(&addr6, &n_addr, sizeof(struct in6_addr)) == 0) {
      
      return true;
    }
  }
  if (next == NULL)
    return false;
  return next->contains(n_addr);
}

bool local_addr::contains(const in_addr_t &n_addr) {
  if ((sa_family == AF_INET) && (n_addr == addr))
    return true;
  if (next == NULL)
    return false;
  return next->contains(n_addr);
}

//packet
local_addr *local_addrs = NULL;

/*
 * getLocal
 *	device: This should be device explicit (e.g. eth0:1)
 *
 * uses getifaddrs to get addresses of this device, and adds them to the
 * local_addrs-list.
 */

typedef u_int32_t tcp_seq;

/* ppp header, i hope ;) */
/* glanced from ethereal, it's 16 bytes, and the payload packet type is
 * in the last 2 bytes... */
struct ppp_header {
  u_int16_t dummy1;
  u_int16_t dummy2;
  u_int16_t dummy3;
  u_int16_t dummy4;
  u_int16_t dummy5;
  u_int16_t dummy6;
  u_int16_t dummy7;

  u_int16_t packettype;
};

/* TCP header */
// TODO take from elsewhere.
struct tcp_hdr {
  u_short th_sport; /* source port */
  u_short th_dport; /* destination port */
  tcp_seq th_seq;   /* sequence number */
  tcp_seq th_ack;   /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
  u_int th_x2 : 4, /* (unused) */
      th_off : 4;  /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
  u_int th_off : 4, /* data offset */
      th_x2 : 4;    /* (unused) */
#endif
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
  u_short th_win; /* window */
  u_short th_sum; /* checksum */
  u_short th_urp; /* urgent pointer */
};
Packet::Packet(in_addr m_sip, unsigned short m_sport, in_addr m_dip,
               unsigned short m_dport, u_int32_t m_len, timeval m_time,
               direction m_dir) {
  sip = m_sip;
  sport = m_sport;
  dip = m_dip;
  dport = m_dport;
  len = m_len;
  time = m_time;
  dir = m_dir;
  sa_family = AF_INET;
  hashstring = NULL;
}

Packet::Packet(in6_addr m_sip, unsigned short m_sport, in6_addr m_dip,
               unsigned short m_dport, u_int32_t m_len, timeval m_time,
               direction m_dir) {
  sip6 = m_sip;
  sport = m_sport;
  dip6 = m_dip;
  dport = m_dport;
  len = m_len;
  time = m_time;
  dir = m_dir;
  sa_family = AF_INET6;
  hashstring = NULL;
}

direction invert(direction dir) {
  if (dir == dir_incoming)
    return dir_outgoing;
  else if (dir == dir_outgoing)
    return dir_incoming;
  else
    return dir_unknown;
}

Packet *Packet::newInverted() {
  direction new_direction = invert(dir);

  if (sa_family == AF_INET)
    return new Packet(dip, dport, sip, sport, len, time, new_direction);
  else
    return new Packet(dip6, dport, sip6, sport, len, time, new_direction);
}

/* constructs returns a new Packet() structure with the same contents as this
 * one */
Packet::Packet(const Packet &old_packet) {
  sip = old_packet.sip;
  sport = old_packet.sport;
  sip6 = old_packet.sip6;
  dip6 = old_packet.dip6;
  dip = old_packet.dip;
  dport = old_packet.dport;
  len = old_packet.len;
  time = old_packet.time;
  sa_family = old_packet.sa_family;
  if (old_packet.hashstring == NULL)
    hashstring = NULL;
  else
    hashstring = strdup(old_packet.hashstring);
  dir = old_packet.dir;
}

bool sameinaddr(in_addr one, in_addr other) {
  return one.s_addr == other.s_addr;
}

bool samein6addr(in6_addr one, in6_addr other) {
  return std::equal(one.s6_addr, one.s6_addr + 16, other.s6_addr);
}

bool Packet::isOlderThan(timeval t) {
  std::cout << "Comparing " << time.tv_sec << " <= " << t.tv_sec << std::endl;
  return (time.tv_sec <= t.tv_sec);
}

bool Packet::Outgoing() {
  /* must be initialised with getLocal("eth0:1");) */
  assert(local_addrs != NULL);

  switch (dir) {
  case dir_outgoing:
    return true;
  case dir_incoming:
    return false;
  case dir_unknown:
  printf("unknown dir\n");
    bool islocal;
    if (sa_family == AF_INET)
      islocal = local_addrs->contains(sip.s_addr);
    else
      islocal = local_addrs->contains(sip6);
    if (islocal) {
      dir = dir_outgoing;
      return true;
    } else {
     {
        if (sa_family == AF_INET)
          islocal = local_addrs->contains(dip.s_addr);
        else
          islocal = local_addrs->contains(dip6);

        if (!islocal) {
          std::cerr << "Neither dip nor sip are local: ";
          char addy[50];
          inet_ntop(AF_INET6, &sip6, addy, 49);
          std::cerr << addy << std::endl;
          inet_ntop(AF_INET6, &dip6, addy, 49);
          std::cerr << addy << std::endl;

          return false;
        }
      }
      dir = dir_incoming;
      return false;
    }
  }
  return false;
}

/* returns the packet in '1.2.3.4:5-1.2.3.4:5'-form, for use in the 'conninode'
 * table */
/* '1.2.3.4' should be the local address. */
char *Packet::gethashstring() {
  if (hashstring != NULL) {
    return hashstring;
  }

  // TODO free this value in the Packet destructor
  hashstring = (char *)malloc(HASHKEYSIZE * sizeof(char));

  char *local_string = (char *)malloc(50);
  char *remote_string = (char *)malloc(50);
  if (sa_family == AF_INET) {
    inet_ntop(sa_family, &sip, local_string, 49);
    inet_ntop(sa_family, &dip, remote_string, 49);
  } else {
    inet_ntop(sa_family, &sip6, local_string, 49);
    inet_ntop(sa_family, &dip6, remote_string, 49);
  }
  if (Outgoing()) {
    snprintf(hashstring, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d",
             local_string, sport, remote_string, dport);
  } else {
    snprintf(hashstring, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d",
             remote_string, dport, local_string, sport);
  }
  free(local_string);
  free(remote_string);
  // if (DEBUG)
  //	std::cout << "Returning newly created hash string: " << hashstring <<
  // std::endl;
  return hashstring;
}

/* 2 packets match if they have the same
 * source and destination ports and IP's. */
bool Packet::match(Packet *other) {
  return sa_family == other->sa_family && (sport == other->sport) &&
         (dport == other->dport) &&
         (sa_family == AF_INET
              ? (sameinaddr(sip, other->sip)) && (sameinaddr(dip, other->dip))
              : (samein6addr(sip6, other->sip6)) &&
                    (samein6addr(dip6, other->dip6)));
}

bool Packet::matchSource(Packet *other) {
  return (sport == other->sport) && (sameinaddr(sip, other->sip));
}

























void addtoconninode(char *buffer) {
  short int sa_family;
  struct in6_addr result_addr_local = {};
  struct in6_addr result_addr_remote = {};

  char rem_addr[128], localaddr[128];
  int local_port, rem_port;
  struct in6_addr in6_local;
  struct in6_addr in6_remote;

  
  unsigned long inode;

  int matches = sscanf(buffer, "%*d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %*X "
                               "%*X:%*X %*X:%*X %*X %*d %*d %ld %*512s\n",
                       localaddr, &local_port, rem_addr, &rem_port, &inode);

  if (matches != 5) {
    fprintf(stderr, "Unexpected buffer: '%s'\n", buffer);
    exit(0);
  }

  //if (inode == 0) {
    /* connection is in TIME_WAIT state. We rely on
     * the old data still in the table. */
    //return;
  //}

  if (strlen(localaddr) > 8) {
    /* this is an IPv6-style row */

    /* Demangle what the kernel gives us */
    sscanf(localaddr, "%08X%08X%08X%08X", &in6_local.s6_addr32[0],
           &in6_local.s6_addr32[1], &in6_local.s6_addr32[2],
           &in6_local.s6_addr32[3]);
    sscanf(rem_addr, "%08X%08X%08X%08X", &in6_remote.s6_addr32[0],
           &in6_remote.s6_addr32[1], &in6_remote.s6_addr32[2],
           &in6_remote.s6_addr32[3]);

    if ((in6_local.s6_addr32[0] == 0x0) && (in6_local.s6_addr32[1] == 0x0) &&
        (in6_local.s6_addr32[2] == 0xFFFF0000)) {
      /* IPv4-compatible address */
      result_addr_local.s6_addr32[0]  = in6_local.s6_addr32[3];
      result_addr_remote.s6_addr32[0] = in6_remote.s6_addr32[3];
      sa_family = AF_INET;
    } else {
      /* real IPv6 address */
      // inet_ntop(AF_INET6, &in6_local, addr6, sizeof(addr6));
      // INET6_getsock(addr6, (struct sockaddr *) &localaddr);
      // inet_ntop(AF_INET6, &in6_remote, addr6, sizeof(addr6));
      // INET6_getsock(addr6, (struct sockaddr *) &remaddr);
      // localaddr.sin6_family = AF_INET6;
      // remaddr.sin6_family = AF_INET6;
      result_addr_local = in6_local;
      result_addr_remote = in6_remote;
      sa_family = AF_INET6;
    }
  } else {
    /* this is an IPv4-style row */
    sscanf(localaddr, "%X", (unsigned int *)&result_addr_local);
    sscanf(rem_addr, "%X", (unsigned int *)&result_addr_remote);
    sa_family = AF_INET;
  }

  printf("local addr:%s\n",localaddr);
  printf("local addr:%s\n############",rem_addr);


   char *hashkey = (char *)malloc(HASHKEYSIZE * sizeof(char));
  char *local_string = (char *)malloc(50);
  char *remote_string = (char *)malloc(50);
  inet_ntop(sa_family, &result_addr_local, local_string, 49);
  inet_ntop(sa_family, &result_addr_remote, remote_string, 49);

  snprintf(hashkey, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d", local_string,
           local_port, remote_string, rem_port);
  free(local_string);
  printf("%s hashkey", hashkey);
  conninode[hashkey] = inode;
  printf("inode%d\n",inode);




}
void printConninode(){
	printf("size%d",conninode.size());
	for( map<std::string,unsigned long>::iterator ii=conninode.begin(); ii!=conninode.end(); ++ii)

	   {

	       printf("%c :%ld\n",(*ii).first,(*ii).second);
	   }

}

int addprocinfo(const char *filename) {
	printf("hi");
  FILE *procinfo = fopen(filename, "r");

  char buffer[8192];

  if (procinfo == NULL)
    return 0;
printf("opening \n");

  fgets(buffer, sizeof(buffer), procinfo);

  do {
    if (fgets(buffer, sizeof(buffer), procinfo))
      addtoconninode(buffer);
  } while (!feof(procinfo));

  fclose(procinfo);

  return 1;
}
/**
*ADDING IP TO THE DEVICE
**/
bool getLocal(const char *device) {
  struct ifaddrs *ifaddr, *ifa;

  if (getifaddrs(&ifaddr) == -1) {
    return false;
  }

  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    if (strcmp(ifa->ifa_name, device) != 0)
      continue;

    int family = ifa->ifa_addr->sa_family;

    if (family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
       local_addrs = new local_addr(addr->sin_addr.s_addr, local_addrs);

     
        printf("Adding local address: %s\n", inet_ntoa(addr->sin_addr));
      
    } else if (family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
     local_addrs = new local_addr(&addr->sin6_addr, local_addrs);
      //DEBUG
        char host[512];
        printf("Adding local address: %s\n",
               inet_ntop(AF_INET6, &addr->sin6_addr, host, sizeof(host)));
      
    }
  }
  return true;
}
/*
*DISPLAY OF NETWORK STATS
**/

// Display all processes and relevant network traffic using show function
unsigned refreshcount = 0;

void do_refresh() {
  //refreshconninode();
  addprocinfo("/proc/net/tcp");
  refreshcount++;

  /*if (viewMode == VIEWMODE_KBPS) {
    remove_timed_out_processes();
  }*/

  ProcList *curproc = processes;
  int nproc = processes->size();

  /* initialize to null pointers */
  Line *lines[nproc];
  for (int i = 0; i < nproc; i++)
    lines[i] = NULL;

  int n = 0;

  while (curproc != NULL) {
    // walk though its connections, summing up their data, and
    // throwing away connections that haven't received a package
    // in the last CONNTIMEOUT seconds.
    assert(curproc->getVal() != NULL);
    assert(nproc == processes->size());

    float value_sent = 0, value_recv = 0;

    //if (viewMode == VIEWMODE_KBPS) {
      curproc->getVal()->getkbps(&value_recv, &value_sent);
    /*} else if (viewMode == VIEWMODE_TOTAL_KB) {
      curproc->getVal()->gettotalkb(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_TOTAL_MB) {
      curproc->getVal()->gettotalmb(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_TOTAL_B) {
      curproc->getVal()->gettotalb(&value_recv, &value_sent);
    } else {
      forceExit(false, "Invalid viewMode: %d", viewMode);
    }*/
    uid_t uid = curproc->getVal()->getUid();
    assert(curproc->getVal()->pid >= 0);
    assert(n < nproc);
    printf("%s proc name %d\n",curproc->getVal()->name,n);

    lines[n] = new Line(curproc->getVal()->name, curproc->getVal()->cmdline,
                        value_recv, value_sent, curproc->getVal()->pid, uid,
                        curproc->getVal()->devicename);
    curproc = curproc->next;
    n++;
  }
  printf(" nproc %d\n",n);

  /* sort the accumulated lines */
  //qsort(lines, nproc, sizeof(Line *), GreatestFirst);

  //if (tracemode || DEBUG)
  printf("\n\n\n\n@@@@@@@@@@@@@@@@@@!!!!!!!!!!!!!!!!!!!OUTPUT!!!!!!!!!!!!!!!@@@@@@@@@@@@@@@@@@@\n\n\n\n");
   show_trace(lines, nproc);
  //else
    //show_ncurses(lines, nproc);

 /* if (refreshlimit != 0 && refreshcount >= refreshlimit)
    quit_cb(0);
*/
}







static handle *handles = NULL;


int main(int argc, char ** argv){
	char fname[20]="/proc/net/tcp";
	printf("hi\n");
	process_init();
	addprocinfo(fname);
	printConninode();

	device *devices=get_devices();
	printDevices(devices);
	device *current_dev=devices;
	int nb_devices=0;
	while (current_dev != NULL) {
    ++nb_devices;

    getLocal(current_dev->name);
    


    dp_handle *newhandle =
        dp_open_live(current_dev->name, BUFSIZ, promisc, 100, errbuf);
    if (newhandle != NULL) {
      dp_addcb(newhandle, dp_packet_ip, process_ip);
      dp_addcb(newhandle, dp_packet_ip6, process_ip6);
      dp_addcb(newhandle, dp_packet_tcp, process_tcp);
      //dp_addcb(newhandle, dp_packet_udp, process_udp);
  }
  if(newhandle !=NULL)
  printf("1480::::%s:%d\n",current_dev->name,newhandle->userdata_size);
  handles = new handle(newhandle, current_dev->name, handles);
  current_dev=current_dev->next;

}
printf("n of devices %d",nb_devices);
printHandles(handles);

struct dpargs *userdata = (dpargs *)malloc(sizeof(struct dpargs));
int count =0;
while(1){
    bool packets_read = false;
    printf("%d null check",(handles->next->next==NULL));
    for (handle *current_handle = handles; current_handle->next != NULL;
         current_handle = current_handle->next) {
     // current_handle=current_handle->next;
    //current_handle=current_handle->next;
      userdata->device = current_handle->devicename;

      userdata->sa_family = AF_UNSPEC;
      printf("hi here %s \n" ,current_handle->devicename);
      
      if(current_handle->content ==NULL || strcmp(current_handle->devicename,"lo")==0)
      {	printf("%s m null\n",current_handle->devicename);
    continue;}

    int retval = dp_dispatch(current_handle->content, 0, (u_char *)userdata,
                            sizeof(struct dpargs));
//int retval=0;
     printf("retval :%d\n",retval );
       if (retval == -1)
        std::cout<< "Error dispatching for device " << current_handle->devicename<<std::endl;
      else if (retval < 0)
        std::cout << "Error dispatching for device " << current_handle->devicename << std::endl;
      else if (retval != 0)
        packets_read = true;
    }
    printf("will be refereshing now");
    time_t const now = ::time(NULL);
    if (last_refresh_time + refreshdelay <= now) {
      last_refresh_time = now;
     
     do_refresh();
    }
count++;
printf("COUNT IS !!!!!!!!!!!!!!!!!!!!!!%d",count);
}





	return 0;
}

