#ifndef __ConnList_H
#define __ConnList_H

#include <cassert>
#include "connection.h"
class Connection;
class ConnList {
public:
  ConnList(Connection *m_val, ConnList *m_next);
  ~ConnList() {
    /* does not delete its value, to allow a connection to
     * remove itself from the global connlist in its destructor */
  }
  Connection *getVal() { return val; }
  void setNext(ConnList *m_next) { next = m_next; }
  ConnList *getNext() { return next; }

private:
  Connection *val;
  ConnList *next;
};
#endif
