/**
 * pcap file reader/writer.
 *
 * @author Zoltan Bojthe
 */

#ifndef __INET_UTIL_IPDATAGRAMPCAPENTRYPARSER_H
#define __INET_UTIL_IPDATAGRAMPCAPENTRYPARSER_H


#include "PcapEntryParserIf.h"


class IPDatagramPcapEntryParser : public PcapEntryParserIf
{
  public:
    virtual ~IPDatagramPcapEntryParser() {};
    virtual cPacket* parse(const unsigned char *buf, uint32_t caplen, uint32_t totlen);
};


#endif // __INET_UTIL_IPDATAGRAMPCAPENTRYPARSER_H
