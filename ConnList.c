#include "connection.h"
#include "ConnList.h"
#include <stdlib.h>
typedef int bool;
void ConnList_init(ConnList *clist,Connection *m_val, ConnList *m_next) {
    //assert(m_val != NULL);
   clist->val = m_val;
    clist->next = m_next;
  }
  Connection *ConnListgetVal(ConnList *clist)
  { return clist->val; }
   void setNext(ConnList *clist,ConnList *m_next) { clist->next = m_next; }
    ConnList *getNext(ConnList *clist) { return clist->next; }