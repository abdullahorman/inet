/**
 * pcap file reader/writer.
 *
 * @author Zoltan Bojthe
 */

#ifndef __INET_UTIL_PCAPFILE_H
#define __INET_UTIL_PCAPFILE_H


#include "INETDefs.h"


// Foreign declarations
#ifndef lib_pcap_pcap_h
typedef void *pcap_t;
typedef void *pcap_dumper_t;
#endif

#if 0
class PcapFileWriter
{
  protected:
    pcap_t *pcap;
    pcap_dumper_t *pcapDumper;
    uint32  snapLen;
  public:
    PcapFileWriter();
    ~PcapFileWriter();
    void open(const char* filename, unsigned int snaplen);
    void close();
    bool isOpen() { return NULL != pcapDumper; }
    void write(uint32_t sec, uint32_t usec, const void *buff, uint32_t capLen, uint32_t fullLen);
};
#endif

class PcapFileReader
{
  protected:
    pcap_t *pcap;
    fpos_t pos0;
  public:
    PcapFileReader() : pcap(NULL) {}
    virtual ~PcapFileReader();
    void open(const char* filename);
    void close();
    bool eof();
    bool isOpen() { return NULL != pcap; }
    void restart();
    const void* read(uint32_t &sec, uint32_t &usec, uint32_t &capLen, uint32_t& origLen);
};

#endif //__INET_UTIL_PCAPFILE_H
