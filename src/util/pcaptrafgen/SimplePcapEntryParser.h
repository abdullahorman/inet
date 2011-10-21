/**
 * pcap file reader/writer.
 *
 * @author Zoltan Bojthe
 */

#ifndef __INET_UTIL_SIMPLEPCAPENTRYPARSER_H
#define __INET_UTIL_SIMPLEPCAPENTRYPARSER_H


#include "PcapEntryParserIf.h"

/*
 * Simple pcap entry parser
 *
 * Create a ~ByteArrayMessage from the pcap entry.
 * Stores `caplen' bytes in packet, and packet length is `totlen'.
 */
class SimplePcapEntryParser : public PcapEntryParserIf
{
  public:
    virtual ~SimplePcapEntryParser() {};
    virtual cPacket* parse(const unsigned char *buf, uint32_t caplen, uint32_t totlen);
};

#endif // __INET_UTIL_SIMPLEPCAPENTRYPARSER_H
