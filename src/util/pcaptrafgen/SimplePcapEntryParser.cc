/**
 * Simple pcap entry parser.
 *
 * @author Zoltan Bojthe
 */

#include <stdio.h>

#include "SimplePcapEntryParser.h"

#include "ByteArrayMessage.h"


Register_Class(SimplePcapEntryParser);

cPacket* SimplePcapEntryParser::parse(const unsigned char *buf, uint32 caplen, uint32 totlen)
{
    char str[50];
    sprintf(str, "PCAP:%u/%u bytes", caplen, totlen);
    ByteArrayMessage* ret = new ByteArrayMessage(str);
    ret->setDataFromBuffer(buf, caplen);
    ret->setByteLength(totlen);
    return ret;
}

