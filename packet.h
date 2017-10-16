#ifndef __PACKET_H
#define __PACKET_H
#include <netinet/in.h>
//#include <in6addr>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>

#include <arpa/inet.h>

typedef struct _Packet Packet;

enum direction { dir_unknown, dir_incoming, dir_outgoing };

/* To initialise this module, call getLocal with the currently
 * monitored device (e.g. "eth0:1") */
bool getLocal(const char *device, bool tracemode);

struct _Packet{
    direction dir;
  short int sa_family;
  char *hashstring;



  in6_addr sip6;
  in6_addr dip6;
  in_addr sip;
  in_addr dip;
  unsigned short sport;
  unsigned short dport;
  u_int32_t len;
  timeval time;
};
  void Packet_init_in_addr(Packet *pk,in_addr m_sip, unsigned short m_sport, in_addr m_dip,
         unsigned short m_dport, u_int32_t m_len, timeval m_time,
         direction dir = dir_unknown);
  void Packet_init_in6_addr(Packet *pk,in6_addr m_sip, unsigned short m_sport, in6_addr m_dip,
         unsigned short m_dport, u_int32_t m_len, timeval m_time,
         direction dir = dir_unknown);
  
  /* copy constructor */
  void Packet_init(Packet *pk,const Packet &old);
  
  /* Packet (const Packet &old_packet); */
  /* copy constructor that turns the packet around */
  Packet *newInverted(Packet *pk);

  bool Packet_isOlderThan(timeval t);
  /* is this packet coming from the local host? */
  bool Outgoing(Packet *pk);

  bool Packet_match(Packet *pk,Packet *other);
  bool Packet_matchSource(Packet *pk,Packet *other);
  /* returns '1.2.3.4:5-1.2.3.4:6'-style string */
  char * gethashstring(Packet *pk);



#endif
