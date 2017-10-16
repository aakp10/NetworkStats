#include <stdio.h>
#include <assert.h>

#include <stdlib.h>


#include "connection.h"
#include "ConnList.h"
#define PERIOD 5


 ConnList *connections ;
 void PackListNode_init(PackListNode *pkList,Packet *m_val, PackListNode *m_next) {
    pkList->val = m_val;
    pkList->next = m_next;
  }
  void PackList_init_beg(PackList *pkList) { pkList->content = NULL; }
  void PackList_init(PackList *pkList,Packet *m_val) {
    //assert(m_val != NULL);
    PackListNode *pkNode=(PackListNode *)malloc(sizeof(PackListNode));
    PackListNode_init(pkNode,m_val,NULL);
    pkList->content = pkNode;
  }

void addPacket(PackList *pkList,Packet *p) {
  if (pkList->content == NULL) {
    Packet *pk=(Packet *)malloc(sizeof(Packet));
    Packet_init(pk,*p);
    PackListNode *pkNode=(PackListNode *)malloc(sizeof(PackListNode));
    PackListNode_init(pkNode,pk,NULL);
    pkList->content = pkNode;
    return;
  }

  if (pkList->content->val->time.tv_sec == p->time.tv_sec) {
    pkList->content->val->len += p->len;
    return;
  }

  /* store copy of packet, so that original may be freed */
Packet *pk=(Packet *)malloc(sizeof(Packet));
    Packet_init(pk,*p);
    PackListNode *pkNode=(PackListNode *)malloc(sizeof(PackListNode));
    PackListNode_init(pkNode,pk,pkList->content);

  pkList->content = pkNode;
}

void addConnection(Connection *conn,Packet *packet) {
  conn->lastpacket = packet->time.tv_sec;
  if (Outgoing(packet)) {
     {
      printf("OUTGOING:%d \n",packet->len);
    }
    conn->sumSent += packet->len;
    addPacket(conn->sent_packets,packet);
    
  } else {
     {
      printf("Incoming:%d \n",packet->len);
    }
    conn->sumRecv += packet->len;
    {
      printf("Incoming:%d \n",conn->sumRecv);
    }
    addPacket(conn->recv_packets,packet);
    
  }
}



void Connection_init(Connection *conn,Packet *packet){
  //assert(packet != NULL);
  ConnList *temp = (ConnList *)malloc(sizeof(ConnList));
  ConnList_init(temp,conn, connections);
  connections=temp;
  conn->sent_packets =(PackList *)malloc(sizeof(PackList));
  PackList_init_beg(conn->sent_packets);

  conn->recv_packets =(PackList *)malloc(sizeof(PackList));
  PackList_init_beg(conn->sent_packets);
  conn->sumSent = 0;
  conn->sumRecv = 0;
  
  if (Outgoing(packet)) {
    conn->sumSent += packet->len;
    
    addPacket(conn->sent_packets,packet);
    conn->refpacket =(Packet *)malloc(sizeof(Packet));
     Packet_init(conn->refpacket,*packet);
  } else {
    conn->sumRecv += packet->len;
    addPacket(conn->recv_packets,packet);
    conn->refpacket = newInverted(packet);
  }
  conn->lastpacket = packet->time.tv_sec;
  
}

int getLastPacket(Connection *conn) { return conn->lastpacket; }

u_int64_t PackList_sumanddel(PackList *pklist,timeval t) {
  u_int64_t retval = 0;
  PackListNode *current = pklist->content;
  PackListNode *previous = NULL;
  printf("value of t :%d",t.tv_sec);

  while (current ==NULL ? 0:current->next  ) {
    // std::cout << "Comparing " << current->val->time.tv_sec << " <= " <<
    // t.tv_sec - PERIOD << endl;
    if (current->val->time.tv_sec <= t.tv_sec - PERIOD) {

      if (current == pklist->content)
        pklist->content = NULL;
      else if (previous != NULL)
        previous->next = NULL;
      //free(current) ;
      current=NULL;
      return retval;
    }
    retval += current->val->len;
    previous = current;
    current = current->next;
  }
  return retval;
}


 void Connection_sumanddel(Connection *conn,timeval t, u_int64_t *recv, u_int64_t *sent) {
  (*sent) = (*recv) = 0;
  printf("tval :%d",t.tv_sec);
  *sent = PackList_sumanddel(conn->sent_packets,t);
  *recv = PackList_sumanddel(conn->recv_packets,t);

}


Connection *findConnectionWithMatchingSource(Packet *packet) {
  //assert(packet->Outgoing());

  ConnList *current = connections;
  while (current != NULL) {
    /* the reference packet is always outgoing */
    if (Packet_matchSource(packet,ConnListgetVal(current)->refpacket)) {
      return ConnListgetVal(current);
    }

    current = getNext(current);
  }
  return NULL;
}

Connection *findConnectionWithMatchingRefpacketOrSource(Packet *packet) {
  ConnList *current = connections;
  while (current != NULL) {
    /* the reference packet is always *outgoing* */
    if (Packet_match(packet,ConnListgetVal(current)->refpacket)) {
      return ConnListgetVal(current);
    }


    current = getNext(current);
  }
  return findConnectionWithMatchingSource(packet);
}


Connection * findConnection(Packet *packet) {
  if (Outgoing(packet))
    return findConnectionWithMatchingRefpacketOrSource(packet);
  else {
    Packet *invertedPacket = newInverted(packet);
    Connection *result =
        findConnectionWithMatchingRefpacketOrSource(invertedPacket);

    free(invertedPacket);
    return result;
  }
}