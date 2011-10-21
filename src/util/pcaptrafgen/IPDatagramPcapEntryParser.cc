/**
 * pcap file reader/writer.
 *
 * @author Zoltan Bojthe
 */

#include <stdio.h>

#include "IPDatagramPcapEntryParser.h"

#include "Ieee802Ctrl_m.h"
#include "IPv4Datagram.h"
#include "IPv6Datagram.h"
#include "IPv4Serializer.h"


#if !defined(_WIN32) && !defined(__WIN32__) && !defined(WIN32) && !defined(__CYGWIN__) && !defined(_WIN64)
#include <netinet/in.h>  // htonl, ntohl, ...
#endif


Register_Class(IPDatagramPcapEntryParser);

#define ETHERNET_LENGTH_MAX 1500

namespace
{
    bool isIPv4Header(const unsigned char *buf, uint32 len)
    {
        if ((buf[0] & 0xF0) != 0x40)
            return false;
        if (len < (unsigned int)IP_HEADER_BYTES)
            return false;
        unsigned int hlen = (buf[0] & 0x0F) * 4;
        if (hlen < (unsigned int)IP_HEADER_BYTES || hlen > (unsigned int)IP_MAX_HEADER_BYTES)
            return false;
        unsigned int dglen = ((unsigned int)(buf[2])<<8) + buf[3];
        if (dglen < hlen || dglen > len)
            return false;
        return true;
    }

    bool isIPv6Header(const unsigned char *buf, uint32 len)
    {
        if ((buf[0] & 0xF0) != 0x60)
            return false;
        if (len < (unsigned int)IPv6_HEADER_BYTES)
            return false;
        unsigned int dglen = ((unsigned int)(buf[4])<<8) + buf[5];
        if ((unsigned int)IPv6_HEADER_BYTES + dglen > len)
            return false;
        return true;
    }
}

struct ethhdr {
    u_char destmac[6];              /* dest MAC addr */
    u_char srcmac[6];               /* src MAC addr */
    u_short length_or_type;         /* length or type */
// end of ETH header
    u_char dsap;
    u_char ssap;
    u_char ctrl;
// end of LLC header
    unsigned int orgcode:24;
    u_short ethtype;
// end of SNAP header
};

#define ETHERNET_LENGTH_MAX 1500

cPacket* IPDatagramPcapEntryParser::parse(const unsigned char *buf, uint32 caplen, uint32 totlen)
{
    if (caplen < totlen)
    {
        EV << "Pcap parser skip a truncated frame: total length=" << totlen << ", captured length=" << caplen << endl;
        return NULL;
    }

    unsigned int hdrlen = 0;
    uint16_t type = 0;

    // test loopback header:
    uint32_t x = *(const uint32_t*)buf;
    switch (x)
    {
        case 2:
        case 2<<24:     // AF_INET
            if (isIPv4Header(buf+4, totlen-4))
            {
                type = ETHERTYPE_IP;
                hdrlen = 4;
            }
            break;

        case 24:
        case 24<<24:
        case 28:
        case 28<<24:
        case 30:
        case 30<<24:    // AF_INET6
            if (isIPv6Header(buf+4, totlen-4))
            {
                type = ETHERTYPE_IPv6;
                hdrlen = 4;
            }
            break;

        default:
            break;
    }

    if (hdrlen == 0)
    {
        // test ethernet header:
        struct ethhdr *ethhdr = (struct ethhdr*) buf;

        uint16_t lenOrType = ntohs(ethhdr->length_or_type);
        if (lenOrType > ETHERNET_LENGTH_MAX)
        {
            // Ethernet II frame
            hdrlen = 14;
            type = lenOrType;
        }
        else if ((ethhdr->dsap == '\xFF') && (ethhdr->ssap == '\xFF') && totlen > 14)
        {
            // 802.3 frame (RAW) with Netware IPX/SPX traffic
            hdrlen = 14;
            type = 0;   //TODO what is the valid type of packet?
        } else if (ethhdr->dsap == '\xAA' && ethhdr->ssap == '\xAA' && ethhdr->ctrl == '\x03' && totlen > 22)
        {
            // Ethernet with SNAP
            hdrlen = 22;
            type = ntohs(ethhdr->ethtype);
        } else
        {
            // 802.2 frame: Ethernet with LLC
            hdrlen = 17;
            type = 0;   //TODO what is the valid type of packet?
        }
    }

    if (hdrlen == 0)
        return NULL;

    cPacket *encapPacket = NULL;
    switch (type)
    {
        case ETHERTYPE_IP:    // IPv4 protocol
            encapPacket = new IPv4Datagram();
            IPv4Serializer().parse(buf+hdrlen, totlen-hdrlen, (IPv4Datagram *)encapPacket);
            break;

        //TODO Parse other protocols, add more cases if need!

        case ETHERTYPE_ARP:    // ARP protocol
        case ETHERTYPE_RARP:    // RARP protocol
        case ETHERTYPE_IPv6:    // IPv6 protocol
        default:
            break;
    }

    return encapPacket;
}

