/**
 * pcap file reader/writer.
 *
 * @author Zoltan Bojthe
 */

#ifndef __INET_UTIL_INETPCAPFILE_H
#define __INET_UTIL_INETPCAPFILE_H


#include "PcapEntryParserIf.h"
#include "PcapFile.h"


class InetPcapFileReader : public PcapFileReader
{
  protected:
    uint32 sec0;
    uint32 usec0;
    PcapEntryParserIf *parser;
  public:
    InetPcapFileReader() : sec0(0), usec0(0), parser(NULL) {};
    ~InetPcapFileReader() { delete parser; };
    void setParser(const char* parserName);
    void open(const char* filename);
    cPacket* read(simtime_t &stime);
};

#if 0
class InetPcapFileWriter : public PcapFileWriter
{
protected:
    InetPcapSerializerIf *serializer;
  public:
    InetPcapFileWriter() : serializer(NULL) {}
    ~InetPcapFileWriter() { delete serializer; }
    void setSerializer(const char* serializerName);
    void write(cPacket *packet);
};
#endif

#endif //__INET_UTIL_INETPCAPFILE_H
