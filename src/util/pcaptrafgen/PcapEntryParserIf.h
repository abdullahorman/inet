/**
 * pcap entry parser interface.
 *
 * @author Zoltan Bojthe
 */

#ifndef __INET_UTIL_PCAPENTRYPARSERIF_H
#define __INET_UTIL_PCAPENTRYPARSERIF_H


#include "INETDefs.h"


class PcapEntryParserIf : public cObject
{
  public:
    virtual ~PcapEntryParserIf() {};
    virtual cPacket* parse(const unsigned char *buf, uint32_t caplen, uint32_t totlen) = 0;
};

#endif //__INET_UTIL_PCAPENTRYPARSERIF_H
