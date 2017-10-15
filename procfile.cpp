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
typedef struct _Line Line;
struct _Line {
const char *m_name;
  const char *m_cmdline;
  const char *devicename;
  pid_t m_pid;
  uid_t m_uid;
  double sent_value;
  double recv_value;
  
};
void Line_init(Line *ln,const char *name, const char *cmdline, double n_recv_value,
       double n_sent_value, pid_t pid, uid_t uid, const char *n_devicename) {
    assert(pid >= 0);
   // assert(pid <= PID_MAX);
    ln->m_name = name;
    ln->m_cmdline = cmdline;
    ln->sent_value = n_sent_value;
    ln->recv_value = n_recv_value;
    ln->devicename = n_devicename;
    ln->m_pid = pid;
    ln->m_uid = uid;
    assert(ln->m_pid >= 0);
  }

void log(Line *ln) {
  printf("m_pid :%d \t m_uid:%d \tsent_value:%f \trecv value:%f \tname of process:%s \n",ln->m_pid,ln->m_uid,ln->sent_value,ln->recv_value ,ln->m_name);
}

void show_trace(Line *lines, int nproc) {
  
  /* print them */
  for (int i = 0; i < nproc; i++) {
    log(&lines[i]);
    free(lines[i]);
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
typedef struct _Process Process;
struct _Process {

  const unsigned long inode;
  uid_t uid;

  /* the process makes a copy of the name. the device name needs to be stable.
   */
  char *name;
  char *cmdline;
  const char *devicename;
  int pid;
  u_int64_t sent_by_closed_bytes;
  u_int64_t rcvd_by_closed_bytes;

  ConnList *connections;
  };
  void Process_init(Process *proc,const unsigned long m_inode, const char *m_devicename,
          const char *m_name = NULL, const char *m_cmdline = NULL)
       {
    // std::cout << "ARN: Process created with dev " << m_devicename <<
    // std::endl;
   printf("PROC: Process created at %s  \n",proc);
  // printf("device name:%s m_name:%d",m_devicename,m_name); 

    if (m_name == NULL)
      proc->name = NULL;
    else
      proc->name = strdup(m_name);
    printf("process name:%s",proc->name);

    if (m_cmdline == NULL)
      proc->cmdline = NULL;
    else
      proc->cmdline = strdup(m_cmdline);

    proc->devicename = m_devicename;
    proc->connections=NULL;//(ConnList *)malloc(sizeof(ConnList)) ;
    proc->pid = 0;
    proc->uid = 0;
    proc->sent_by_closed_bytes = 0;
    proc->rcvd_by_closed_bytes = 0;
  }
  //void check() { assert(pid >= 0); }

  
  
  int getLastPacket(Process *proc){
  	int lastpacket = 0;
  ConnList *curconn = proc->connections;
  while (curconn != NULL) {
    assert(curconn != NULL);
    assert(ConnListgetVal(curconn) != NULL);
    if (getLastPacket(ConnListgetVal(curconn)) > lastpacket)
      lastpacket = getLastPacket(ConnListgetVal(curconn));
    curconn = getNext(curconn);
  }
  return lastpacket;
  }

  void Process_gettotal(Process *proc, u_int64_t *recvd, u_int64_t *sent){
  u_int64_t sum_sent = 0, sum_recv = 0;
  ConnList *curconn = proc->connections;
  while (curconn != NULL) {
    Connection *conn = ConnListgetVal(curconn);
    sum_sent += conn->sumSent;
    sum_recv += conn->sumRecv;
    curconn = getNext(curconn);
  }
  printf("Sum sent: %d",sum_sent);
  printf("Sum recv: %d",sum_recv);
  // std::cout << "Sum recv: " << sum_recv << std::endl;
  *recvd = sum_recv + proc->rcvd_by_closed_bytes;
  *sent = sum_sent + proc->sent_by_closed_bytes;
}


float tokb(u_int64_t bytes) { return ((double)bytes) / 1024; }
float tokbps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / 1024; }

  void getkbps(Process *proc,float *recvd, float *sent){
  u_int64_t sum_sent = 0, sum_recv = 0;

  /* walk though all this process's connections, and sum
   * them up */
  ConnList *curconn = proc->connections;
  ConnList *previous = NULL;
  while (curconn != NULL) {
    if (getLastPacket(ConnListgetVal(curconn)) <= curtime.tv_sec - CONNTIMEOUT) {
      /* capture sent and received totals before deleting */
      proc->sent_by_closed_bytes += ConnListgetVal(curconn)->sumSent;
      proc->rcvd_by_closed_bytes += ConnListgetVal(curconn)->sumRecv;
      /* stalled connection, remove. */
      ConnList *todelete = curconn;
      Connection *conn_todelete = ConnListgetVal(curconn);
      curconn = getNext(curconn);
      if (todelete == proc->connections)
        proc->connections = curconn;
      if (previous != NULL)
        setNext(previous,curconn);
      free (todelete);
      free (conn_todelete);
    } else {
      u_int64_t sent = 0, recv = 0;
      Connection_sumanddel(ConnListgetVal(curconn),curtime, &recv, &sent);
      sum_sent += sent;
      sum_recv += recv;
      previous = curconn;
      curconn = getNext(curconn);
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
/*void gettotalkb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  *recvd = tokb(sum_recv);
  *sent = tokb(sum_sent);
}*/

  /*void gettotalb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  // std::cout << "Total sent: " << sum_sent << std::endl;
  *sent = sum_sent;
  *recvd = sum_recv;
}

 */
  uid_t getUid(Process *proc) { return proc->uid; }

  void setUid(Process *proc,uid_t m_uid) { proc->uid = m_uid; }

  unsigned long getInode(Process *proc) { return proc->inode; }



typedef struct _ProcList ProcList;
struct _ProcList {
 Process *val;
 ProcList *next;
};
  void ProcList_init(ProcList *plist,Process *m_val, ProcList *m_next) {
    assert(m_val != NULL);
    plist->val = m_val;
    plist->next = m_next;
  }
  int size(ProcList *plist){
  int i = 1;

  if (plist->next != NULL)
    i += size(plist->next);

  return i;
}
  Process *ProcListgetVal(ProcList *plist) { return plist->val; }
  ProcList *getNext(ProcList *plist) { return plist->next; }
  
 


Process *unknowntcp=(Process *)malloc(sizeof(Process));
Process *unknownudp=(Process *)malloc(sizeof(Process));
Process *unknownip=(Process *)malloc(sizeof(Process));
ProcList *processes=(ProcList *)malloc(sizeof(ProcList));
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
    Process *currentproc = ProcListgetVal(current);
    assert(currentproc != NULL);

    if (node->pid == currentproc->pid)
      return ProcListgetVal(current);
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

  Process *newproc = (Process *)malloc(sizeof(Process));
   Process_init(newproc,inode, devicename, prgname, cmdline);
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
    setUid(newproc,0);
  else
    setUid(newproc,stats.st_uid);

  /*if (getpwuid(stats.st_uid) == NULL) {
          std::stderr << "uid for inode
          if (!ROBUST)
                  assert(false);
  }*/
                 ProcList *temp=(ProcList *)malloc(sizeof(ProcList));
    ProcList_init( temp,newproc, processes);
    processes=temp;
  //ProcList_init(processes,newproc, processes);
  return newproc;
}


Process *getProcess(Connection *connection, const char *devicename) {
  unsigned long inode = conninode[gethashstring(connection->refpacket)];

  if (inode == 0) {
      /* HACK: the following is a hack for cases where the
       * 'local' addresses aren't properly recognised, as is
       * currently the case for IPv6 */

      /* we reverse the direction of the stream if
       * successful. */
      Packet *reversepacket = newInverted(connection->refpacket);
      inode = conninode[gethashstring(reversepacket)];

      if (inode == 0) {
        free(reversepacket);
        ConnList *temp=(ConnList *)malloc(sizeof(ConnList));
         ConnList_init(temp,connection, unknowntcp->connections);
         unknowntcp->connections=temp;
        return unknowntcp;
      }

      free(connection->refpacket);
      connection->refpacket = reversepacket;
    }

  

  
  Process *proc =NULL;// (Process *)malloc(sizeof(Process));
  if (inode != 0)
    proc = getProcess(inode, devicename);

  if (proc == NULL) {
    proc = (Process *)malloc(sizeof(Process));

    Process_init(proc,inode, "", gethashstring(connection->refpacket));
    ProcList *temp=(ProcList *)malloc(sizeof(ProcList));
    ProcList_init( temp,proc, processes);
    processes=temp;

  }
  ConnList *tempList=(ConnList *)malloc(sizeof(ConnList));

   ConnList_init(tempList,connection, proc->connections);
   proc->connections=tempList;

  return proc;
}




void process_init() {
    Process_init(unknowntcp,0, "", "unknown TCP");
  // unknownudp = new Process (0, "", "unknown UDP");
  // unknownip = new Process (0, "", "unknown IP");
   ProcList_init(processes,unknowntcp, NULL);
  // processes = new ProcList (unknownudp, processes);
  // processes = new ProcList (unknownip, processes);
}

void refreshconninode();

void procclean();

void remove_timed_out_processes();


/**
**Fetching DEVICES
***/

typedef struct _device device;
struct _device {

 
  const char *name;
  device *next;
};
 void device_init(device *dev,const char *m_name, device *m_next = NULL) {
    dev->name = m_name;
    dev->next = m_next;
  }



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
  printf("**fetching dev");
  struct ifaddrs *ifaddr, *ifa;
printf("fetching dev");
  if (getifaddrs(&ifaddr) == -1) {
    printf("Failed to get interface addresses\n" );
    // perror("getifaddrs");
    return NULL;
  }
printf("fetching dev");
  device *nextdevices ;//=(device *)malloc(sizeof(device));
  device *devices;
  device *newdevices=(device *)malloc(sizeof(device));
  devices=newdevices;
  //= (device *)malloc(sizeof(device));
  printf("mem alloc dev");
  int count=0;
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
  		if(newdevices)
  	{	 const char * name=strdup(ifa->ifa_name);
  	if ( search(name,newdevices))
  		continue;
  } if(count!=0)
         {newdevices=(device *)malloc(sizeof(device));
         device_init(newdevices,strdup(ifa->ifa_name), nextdevices);
       }
       else if(count==0)
       {
         device_init(newdevices,strdup(ifa->ifa_name));
       }
         nextdevices=newdevices;
         count++;
        
  }
  printf("%d",count);

  freeifaddrs(ifaddr);
  return newdevices;
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
  Packet *packet=(Packet *)malloc(sizeof(Packet));
  switch (args->sa_family) {
  case AF_INET:

    Packet_init(packet,args->ip_src, ntohs(tcp->th_sport), args->ip_dst,
                        ntohs(tcp->th_dport), header->len, header->ts);

//    packet = new Packet(args->ip_src, ntohs(tcp->source), args->ip_dst,
//                        ntohs(tcp->dest), header->len, header->ts);
//#endif
    break;
  case AF_INET6:
 
    Packet_init(packet,args->ip6_src, ntohs(tcp->th_sport), args->ip6_dst,
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
    addConnection(connection,packet);
  } else {
    Connection * connection=(Connection *)malloc(sizeof(Connection));    /* else: unknown connection, create new */
     Connection_init(connection,packet);
    getProcess(connection, args->device);
  }
  free(packet);

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
  return pcap_dispatch(handle->pcap_handle, -1, dp_pcap_callback,
                       (u_char *)handle);
}
/**
*handle to store handles for different devices
**/
typedef struct _handle handle;
struct _handle {
    dp_handle *content;
  const char *devicename;
  handle *next;

  

};
void handle_init(handle *hdl,dp_handle *m_handle, const char *m_devicename = NULL,
         handle *m_next = NULL) {
    hdl->content = m_handle;
    hdl->next = m_next;
    hdl->devicename = m_devicename;
  }

void printHandles(handle *handles){
	for(handle * temp=handles;temp !=NULL;temp=temp->next){
		printf("dev name:%s ,\n",temp->devicename);
	}
}


/**
***Connection hash tables after reading from proc file
***/
typedef struct _local_addr local_addr;
struct _local_addr{

	in_addr_t addr;
	struct in6_addr addr6;
	short int sa_family;

	char *string;
	local_addr *next;
	

//bool contains(const struct in6_addr &n_addr);
//bool contains(const in_addr_t &n_addr);

};

void local_addr_init(local_addr *laddr,in_addr_t m_addr,local_addr *mnext=NULL){
    laddr->addr=m_addr;
    laddr->next=mnext;
    laddr->sa_family=AF_INET6;
    laddr->string=(char *)malloc(16);
    inet_ntop(AF_INET6,&m_addr,laddr->string,15);

  }
void local_addr_init(local_addr *laddr,struct in6_addr *m_addr, local_addr *m_next = NULL) {
    laddr->addr6 = *m_addr;
    laddr->next = m_next;
    laddr->sa_family = AF_INET6;
    laddr->string = (char *)malloc(64);
    inet_ntop(AF_INET6, &m_addr, laddr->string, 63);
  }


bool local_addr_contains(local_addr *laddr,const struct in6_addr &n_addr) {
  if (laddr->sa_family == AF_INET6) {
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
    if (memcmp(&(laddr->addr6), &n_addr, sizeof(struct in6_addr)) == 0) {
      
      return true;
    }
  }
  if (laddr->next == NULL)
    return false;
  return local_addr_contains(laddr->next,n_addr);
}

bool local_addr_contains(local_addr *laddr,const in_addr_t &n_addr) {
  if ((laddr->sa_family == AF_INET) && (n_addr ==laddr->addr))
    return true;
  if (laddr->next == NULL)
    return false;
  return local_addr_contains(laddr->next,n_addr);
}

//packet
local_addr *local_addrs =NULL;//(local_addr *)malloc(sizeof(local_addr));

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
void Packet_init(Packet *pk,in_addr m_sip, unsigned short m_sport, in_addr m_dip,
               unsigned short m_dport, u_int32_t m_len, timeval m_time,
               direction m_dir) {
  pk->sip = m_sip;
  pk->sport = m_sport;
  pk->dip = m_dip;
  pk->dport = m_dport;
  pk->len = m_len;
  pk->time = m_time;
  pk->dir = m_dir;
  pk->sa_family = AF_INET;
  pk->hashstring = NULL;
}

void Packet_init(Packet *pk,in6_addr m_sip, unsigned short m_sport, in6_addr m_dip,
               unsigned short m_dport, u_int32_t m_len, timeval m_time,
               direction m_dir) {
  pk->sip6 = m_sip;
  pk->sport = m_sport;
  pk->dip6 = m_dip;
  pk->dport = m_dport;
  pk->len = m_len;
  pk->time = m_time;
  pk->dir = m_dir;
  pk->sa_family = AF_INET6;
  pk->hashstring = NULL;
}

direction invert(direction dir) {
  if (dir == dir_incoming)
    return dir_outgoing;
  else if (dir == dir_outgoing)
    return dir_incoming;
  else
    return dir_unknown;
}

Packet * newInverted(Packet *pk) {
  direction new_direction = invert(pk->dir);

  if (pk->sa_family == AF_INET)
  {Packet *temp=(Packet *)malloc(sizeof(Packet));
   Packet_init(temp,pk->dip, pk->dport,pk->sip, pk->sport, pk->len, pk->time, new_direction);
    
    return temp;
  }
  
    Packet *temp=(Packet *)malloc(sizeof(Packet));
    Packet_init(temp,pk->dip6, pk->dport, pk->sip6, pk->sport, pk->len, pk->time, new_direction);
    return temp;
  
   
}

/* constructs returns a new Packet() structure with the same contents as this
 * one */
void Packet_init(Packet *pk,const Packet &old_packet) {
  pk->sip = old_packet.sip;
  pk->sport = old_packet.sport;
  pk->sip6 = old_packet.sip6;
  pk->dip6 = old_packet.dip6;
  pk->dip = old_packet.dip;
  pk->dport = old_packet.dport;
  pk->len = old_packet.len;
  pk->time = old_packet.time;
  pk->sa_family = old_packet.sa_family;
  if (old_packet.hashstring == NULL)
    pk->hashstring = NULL;
  else
    pk->hashstring = strdup(old_packet.hashstring);
  pk->dir = old_packet.dir;
}

bool sameinaddr(in_addr one, in_addr other) {
  return one.s_addr == other.s_addr;
}

bool samein6addr(in6_addr one, in6_addr other) {
  return std::equal(one.s6_addr, one.s6_addr + 16, other.s6_addr);
}

bool Packet_isOlderThan(Packet *pk,timeval t) {
  //std::cout << "Comparing " << pk->time.tv_sec << " <= " << t.tv_sec << std::endl;
  return (pk->time.tv_sec <= t.tv_sec);
}

bool Outgoing(Packet *pk) {
  /* must be initialised with getLocal("eth0:1");) */
  assert(local_addrs != NULL);

  switch (pk->dir) {
  case dir_outgoing:
    return true;
  case dir_incoming:
    return false;
  case dir_unknown:
  printf("unknown dir\n");
    bool islocal;
    if (pk->sa_family == AF_INET)
      islocal = local_addr_contains(local_addrs,pk->sip.s_addr);
    else
      islocal = local_addr_contains(local_addrs,pk->sip6);
    if (islocal) {
      pk->dir = dir_outgoing;
      return true;
    } else {
     {
        if (pk->sa_family == AF_INET)
          islocal = local_addr_contains(local_addrs,pk->dip.s_addr);
        else
          islocal = local_addr_contains(local_addrs,pk->dip6);

        if (!islocal) {
          std::cerr << "Neither dip nor sip are local: ";
          char addy[50];
          inet_ntop(AF_INET6, &(pk->sip6), addy, 49);
          std::cerr << addy << std::endl;
          inet_ntop(AF_INET6, &(pk->dip6), addy, 49);
          std::cerr << addy << std::endl;

          return false;
        }
      }
      pk->dir = dir_incoming;
      return false;
    }
  }
  return false;
}

/* returns the packet in '1.2.3.4:5-1.2.3.4:5'-form, for use in the 'conninode'
 * table */
/* '1.2.3.4' should be the local address. */
char * gethashstring(Packet *pk) {
  if (pk->hashstring != NULL) {
    return pk->hashstring;
  }

  // TODO free this value in the Packet destructor
  pk->hashstring = (char *)malloc(HASHKEYSIZE * sizeof(char));

  char *local_string = (char *)malloc(50);
  char *remote_string = (char *)malloc(50);
  if (pk->sa_family == AF_INET) {
    inet_ntop(pk->sa_family, &(pk->sip), local_string, 49);
    inet_ntop(pk->sa_family, &(pk->dip), remote_string, 49);
  } else {
    inet_ntop(pk->sa_family, &(pk->sip6), local_string, 49);
    inet_ntop(pk->sa_family, &(pk->dip6), remote_string, 49);
  }
  if (Outgoing(pk)) {
    snprintf(pk->hashstring, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d",
             local_string, pk->sport, remote_string, pk->dport);
  } else {
    snprintf(pk->hashstring, HASHKEYSIZE * sizeof(char), "%s:%d-%s:%d",
             remote_string, pk->dport, local_string, pk->sport);
  }
  free(local_string);
  free(remote_string);
  // if (DEBUG)
  //	std::cout << "Returning newly created hash string: " << hashstring <<
  // std::endl;
  return pk->hashstring;
}

/* 2 packets match if they have the same
 * source and destination ports and IP's. */
bool Packet_match(Packet *pk,Packet *other) {
  return pk->sa_family == other->sa_family && (pk->sport == other->sport) &&
         (pk->dport == other->dport) &&
         (pk->sa_family == AF_INET
              ? (sameinaddr(pk->sip, other->sip)) && (sameinaddr(pk->dip, other->dip))
              : (samein6addr(pk->sip6, other->sip6)) &&
                    (samein6addr(pk->dip6, other->dip6)));
}

bool Packet_matchSource(Packet *pk,Packet *other) {
  return (pk->sport == other->sport) && (sameinaddr(pk->sip, other->sip));
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
     printf("completed");

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
   local_addr *temp=(local_addr *)malloc(sizeof(local_addr));
       local_addr_init(temp,addr->sin_addr.s_addr, local_addrs);
 local_addrs=temp;
     
        printf("Adding local address: %s\n", inet_ntoa(addr->sin_addr));
      
    } else if (family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)ifa->ifa_addr;
    local_addr *temp=(local_addr *)malloc(sizeof(local_addr));
     local_addr_init(temp,&addr->sin6_addr, local_addrs);
     local_addrs=temp;
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
  int nproc = size(processes);

  /* initialize to null pointers */
  Line *lines=(Line *)calloc(nproc,sizeof(Line));
  /*for (int i = 0; i < nproc; i++)
    lines[i] = NULL;
*/
  int n = 0;

  while (curproc != NULL) {
    // walk though its connections, summing up their data, and
    // throwing away connections that haven't received a package
    // in the last CONNTIMEOUT seconds.
    assert(ProcListgetVal(curproc) != NULL);
    assert(nproc == size(processes));

    float value_sent = 0, value_recv = 0;

    //if (viewMode == VIEWMODE_KBPS) {
      getkbps(ProcListgetVal(curproc),&value_recv, &value_sent);
    /*} else if (viewMode == VIEWMODE_TOTAL_KB) {
      curproc->getVal()->gettotalkb(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_TOTAL_MB) {
      curproc->getVal()->gettotalmb(&value_recv, &value_sent);
    } else if (viewMode == VIEWMODE_TOTAL_B) {
      curproc->getVal()->gettotalb(&value_recv, &value_sent);
    } else {
      forceExit(false, "Invalid viewMode: %d", viewMode);
    }*/
    uid_t uid = getUid(ProcListgetVal(curproc));
    assert(ProcListgetVal(curproc)->pid >= 0);
    assert(n < nproc);
    printf("%s proc name %d\n",ProcListgetVal(curproc)->name,n);

    Line_init(&lines[n],ProcListgetVal(curproc)->name, ProcListgetVal(curproc)->cmdline,
                        value_recv, value_sent, ProcListgetVal(curproc)->pid, uid,
                        ProcListgetVal(curproc)->devicename);
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







static handle *handles = (handle *)malloc(sizeof(handle));


int main(int argc, char ** argv){
	char fname[20]="/proc/net/tcp";
	printf("hi\n");
	process_init();
	addprocinfo(fname);
	printConninode();
	device *devices=get_devices();
printf("fetched dev");

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
handle *tempHandle=(handle *)malloc(sizeof(handle));
  
   handle_init(tempHandle,newhandle, current_dev->name, handles);
   handles=tempHandle;
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

