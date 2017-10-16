#ifndef __ConnList_H
#define __ConnList_H

#include <assert.h>
#include "connection.h"
typedef int bool;
typedef struct _ConnList ConnList;
struct _Connection;
typedef struct _Connection Connection;
struct _ConnList {

  Connection *val;
  ConnList *next;
};

 void  ConnList_init(ConnList *clist,Connection *m_val, ConnList *m_next=NULL);
 
  Connection *ConnListgetVal(ConnList *clist); 
  void setNext(ConnList *clist,ConnList *m_next) ;
  ConnList *getNext(ConnList *clist) ;
#endif
