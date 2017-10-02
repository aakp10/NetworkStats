#ifndef __CONNECTION_H
#define __CONNECTION_H

#include <iostream>
#include "packet.h"
#include "ConnList.h"
class PackListNode {
public:
  PackListNode(Packet *m_val, PackListNode *m_next = NULL) {
    val = m_val;
    next = m_next;
  }
  ~PackListNode() {
    delete val;
    if (next != NULL)
      delete next;
  }
  PackListNode *next;
  Packet *val;
};

class PackList {
public:
  PackList() { content = NULL; }
  PackList(Packet *m_val) {
    //assert(m_val != NULL);
    content = new PackListNode(m_val);
  }
  ~PackList() {
    if (content != NULL)
      delete content;
  }

  /* sums up the total bytes used and removes 'old' packets */
  u_int64_t sumanddel(timeval t);

  /* calling code may delete packet */
  void add(Packet *p);

private:
  PackListNode *content;
};


class Connection {

  /* constructs a connection, makes a copy of
   * the packet as 'refpacket', and adds the
   * packet to the packlist */
  /* packet may be deleted by caller */
private:
  PackList *sent_packets;
  PackList *recv_packets;
  int lastpacket;
public:
  Connection(Packet *packet);

 // ~Connection();

  /* add a packet to the packlist
   * will delete the packet structure
   * when it is 'merged with' (added to) another
   * packet
   */
  void add(Packet *packet);

  int getLastPacket() { return lastpacket; }

  /* sums up the total bytes used
   * and removes 'old' packets. */
  void sumanddel(timeval curtime, u_int64_t *recv, u_int64_t *sent);
  /* for checking if a packet is part of this connection */
  /* the reference packet is always *outgoing*. */
  Packet *refpacket;

  /* total sum or sent/received bytes */
  u_int64_t sumSent;
  u_int64_t sumRecv;



};
Connection *findConnection(Packet *packet);
#endif

