#include <iostream>
#include <cassert>




#include "connection.h"
#include "ConnList.h"
#define PERIOD 5


ConnList *connections = NULL;

void PackList::add(Packet *p) {
  if (content == NULL) {
    content = new PackListNode(new Packet(*p));
    return;
  }

  if (content->val->time.tv_sec == p->time.tv_sec) {
    content->val->len += p->len;
    return;
  }

  /* store copy of packet, so that original may be freed */
  content = new PackListNode(new Packet(*p), content);
}

void Connection::add(Packet *packet) {
  lastpacket = packet->time.tv_sec;
  if (packet->Outgoing()) {
     {
      printf("OUTGOING:%d \n",packet->len);
    }
    sumSent += packet->len;
    sent_packets->add(packet);
  } else {
     {
      printf("Incoming:%d \n",packet->len);
    }
    sumRecv += packet->len;
    {
      printf("Incoming:%d \n",sumRecv);
    }
    recv_packets->add(packet);
  }
}



Connection::Connection(Packet *packet){
  //assert(packet != NULL);
  connections = new ConnList(this, connections);
  sent_packets = new PackList();
  recv_packets = new PackList();
  sumSent = 0;
  sumRecv = 0;
  
  if (packet->Outgoing()) {
    sumSent += packet->len;
    sent_packets->add(packet);
    refpacket = new Packet(*packet);
  } else {
    sumRecv += packet->len;
    recv_packets->add(packet);
    refpacket = packet->newInverted();
  }
  lastpacket = packet->time.tv_sec;
  
}

u_int64_t PackList::sumanddel(timeval t) {
  u_int64_t retval = 0;
  PackListNode *current = content;
  PackListNode *previous = NULL;

  while (current != NULL) {
    // std::cout << "Comparing " << current->val->time.tv_sec << " <= " <<
    // t.tv_sec - PERIOD << endl;
    if (current->val->time.tv_sec <= t.tv_sec - PERIOD) {
      if (current == content)
        content = NULL;
      else if (previous != NULL)
        previous->next = NULL;
      delete current;
      return retval;
    }
    retval += current->val->len;
    previous = current;
    current = current->next;
  }
  return retval;
}


 void Connection::sumanddel(timeval t, u_int64_t *recv, u_int64_t *sent) {
  (*sent) = (*recv) = 0;

  *sent = sent_packets->sumanddel(t);
  *recv = recv_packets->sumanddel(t);
}


Connection *findConnectionWithMatchingSource(Packet *packet) {
  //assert(packet->Outgoing());

  ConnList *current = connections;
  while (current != NULL) {
    /* the reference packet is always outgoing */
    if (packet->matchSource(current->getVal()->refpacket)) {
      return current->getVal();
    }

    current = current->getNext();
  }
  return NULL;
}

Connection *findConnectionWithMatchingRefpacketOrSource(Packet *packet) {
  ConnList *current = connections;
  while (current != NULL) {
    /* the reference packet is always *outgoing* */
    if (packet->match(current->getVal()->refpacket)) {
      return current->getVal();
    }

    current = current->getNext();
  }
  return findConnectionWithMatchingSource(packet);
}


Connection * findConnection(Packet *packet) {
  if (packet->Outgoing())
    return findConnectionWithMatchingRefpacketOrSource(packet);
  else {
    Packet *invertedPacket = packet->newInverted();
    Connection *result =
        findConnectionWithMatchingRefpacketOrSource(invertedPacket);

    delete invertedPacket;
    return result;
  }
}