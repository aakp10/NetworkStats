#ifndef __CONNECTION_H
#define __CONNECTION_H

#include <stdio.h>
#include "packet.h"
#include "ConnList.h"
typedef int bool;
typedef struct _PackListNode PackListNode;
typedef struct _PackList PackList;
typedef struct _Connection Connection;
struct _PackListNode {
PackListNode *next;
Packet *val;
  
};


void PackListNode_init(PackListNode *pkList,Packet *m_val, PackListNode *m_next = NULL) ;

struct _PackList {
  PackListNode *content;

};


void PackList_init_beg(PackList *pkList) ;
void PackList_init(PackList *pkList,Packet *m_val);
/* sums up the total bytes used and removes 'old' packets */
  u_int64_t PackList_sumanddel(PackList *pklist,timeval t);

  /* calling code may delete packet */
  void addPacket(PackList *pklist,Packet *p);

struct _Connection {

  /* constructs a connection, makes a copy of
   * the packet as 'refpacket', and adds the
   * packet to the packlist */
  /* packet may be deleted by caller */

  PackList *sent_packets;
  PackList *recv_packets;
  int lastpacket;
 /* for checking if a packet is part of this connection */
  /* the reference packet is always *outgoing*. */
  Packet *refpacket;

  /* total sum or sent/received bytes */
  u_int64_t sumSent;
  u_int64_t sumRecv;

  
};
void Connection_init(Connection *conn,Packet *packet);

 // ~Connection();

  /* add a packet to the packlist
   * will delete the packet structure
   * when it is 'merged with' (added to) another
   * packet
   */
  void addConnection(Connection *conn,Packet *packet);

  int getLastPacket(Connection *conn);

  /* sums up the total bytes used
   * and removes 'old' packets. */
  void Connection_sumanddel(Connection *conn,timeval curtime, u_int64_t *recv, u_int64_t *sent);
 


Connection *findConnection(Packet *packet);
#endif

