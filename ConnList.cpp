#include "connection.h"
#include "ConnList.h"

ConnList::ConnList(Connection *m_val, ConnList *m_next) {
    assert(m_val != NULL);
    val = m_val;
    next = m_next;
  }