/**
 * pcap file reader/writer.
 *
 * @author Zoltan Bojthe
 */

#include <stdio.h>

#include "InetPcapFile.h"


void InetPcapFileReader::open(const char* filename)
{
    PcapFileReader::open(filename);
    uint32 caplen, origlen;
    // read first packet, for get time of first packet
    PcapFileReader::read(sec0, usec0, caplen, origlen);
    restart();
}

cPacket* InetPcapFileReader::read(simtime_t &stime)
{
    if (!pcap)
        return NULL;

    if (!parser)
        throw cRuntimeError("InetPcapFileReader haven't a parser!");

    uint32 sec, usec, caplen, len;

    const unsigned char* buf = (unsigned char *)PcapFileReader::read(sec, usec, caplen, len);
    if (!buf)
        return NULL;

    // calculate relative time:
    stime = simtime_t((double)(sec-sec0) + (0.000001 * (int32)(usec-usec0)));

    cPacket* ret = parser->parse(buf, caplen, len);
    return ret;
}

#if 0
void InetPcapFileWriter::write(cPacket *packet)
{
    if (!pcapDumper)
        return;

    if (!serializer)
        throw cRuntimeError("InetPcapFileWriter haven't a serializer!");

    uint32 bufLen = snapLen;
    uint8 buf[bufLen];

    memset((void*)buf, 0, snapLen);

    uint32 len = serializer->serialize(packet, buf, bufLen);
    if (len)
    {
        const simtime_t stime = simulation.getSimTime();
        uint32 sec = (uint32)stime.dbl();
        uint32 usec = (uint32)((stime.dbl() - sec)*1000000);
        PcapFileWriter::write(sec, usec, buf, std::min(bufLen, len), len);
    }
}
#endif

void InetPcapFileReader::setParser(const char* parserName)
{
    delete parser;
    parser = check_and_cast<PcapEntryParserIf*>(createOne(parserName));
    if (!parser)
        throw cRuntimeError("InetPcapFileReader: Invalid pcap parser name: %s", parserName);
}

#if 0
void InetPcapFileWriter::setSerializer(const char* serializerName)
{
    delete serializer;
    serializer = check_and_cast<InetPcapSerializerIf*>(createOne(serializerName));
    if (!serializer)
        throw cRuntimeError("InetPcapFileWriter: Invalid pcap serializer name: %s", serializerName);
}
#endif

