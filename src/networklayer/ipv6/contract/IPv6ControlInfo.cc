//
// Copyright (C) 2005 Andras Varga
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "IPv6ControlInfo.h"
#include "IPv6Datagram.h"


void IPv6ControlInfo::copy(const IPv6ControlInfo& other)
{
    dgram = other.dgram;
    if(dgram)
    {
        dgram = dgram->dup();
        take(dgram);
    }

    for (ExtensionHeaders::const_iterator i=other.extensionHeaders.begin(); i!=other.extensionHeaders.end(); i++)
        extensionHeaders.push_back((*i)->dup());
}

IPv6ControlInfo& IPv6ControlInfo::operator=(const IPv6ControlInfo& other)
{
    if (this==&other) return *this;
    clean();
    IPv6ControlInfo_Base::operator=(other);
    copy(other);
    return *this;
}

void IPv6ControlInfo::clean()
{
    if (dgram)
    {
        drop(dgram);
        delete dgram;
    }

    while ( ! extensionHeaders.empty() )
    {
        IPv6ExtensionHeader* eh = extensionHeaders.back();
        extensionHeaders.pop_back();
        delete eh;
    }
}

IPv6ControlInfo::~IPv6ControlInfo()
{
    clean();
}

void IPv6ControlInfo::setOrigDatagram(IPv6Datagram *d)
{
    if (dgram)
        throw cRuntimeError(this, "IPv6ControlInfo::setOrigDatagram(): a datagram is already attached");

    dgram = d;
    take(dgram);
}

IPv6Datagram *IPv6ControlInfo::removeOrigDatagram()
{
    if (!dgram)
        throw cRuntimeError(this, "IPv6ControlInfo::removeOrigDatagram(): no datagram attached "
                  "(already removed, or maybe this IPv6ControlInfo does not come "
                  "from the IPv6 module?)");

    IPv6Datagram *ret = dgram;
    drop(dgram);
    dgram = NULL;
    return ret;
}

unsigned int IPv6ControlInfo::getExtensionHeaderArraySize() const
{
    return extensionHeaders.size();
}

void IPv6ControlInfo::setExtensionHeaderArraySize(unsigned int size)
{
    throw cRuntimeError(this, "setExtensionHeaderArraySize() not supported, use addExtensionHeader()");
}

IPv6ExtensionHeaderPtr& IPv6ControlInfo::getExtensionHeader(unsigned int k)
{
    ASSERT(k>=0 && k<extensionHeaders.size());
    return extensionHeaders[k];
}

void IPv6ControlInfo::setExtensionHeader(unsigned int k, const IPv6ExtensionHeaderPtr& extensionHeader_var)
{
    throw cRuntimeError(this, "setExtensionHeader() not supported, use addExtensionHeader()");
}

void IPv6ControlInfo::addExtensionHeader(IPv6ExtensionHeader* eh, int atPos)
{
    ASSERT(eh);
    if (atPos < 0 || (ExtensionHeaders::size_type)atPos >= extensionHeaders.size())
    {
        extensionHeaders.push_back(eh);
        return;
    }

    // insert at position atPos, shift up the rest of the array
    extensionHeaders.insert(extensionHeaders.begin()+atPos, eh);
}

IPv6ExtensionHeader* IPv6ControlInfo::removeFirstExtensionHeader()
{
    if (extensionHeaders.empty())
        return NULL;

    ExtensionHeaders::iterator first = extensionHeaders.begin();
    IPv6ExtensionHeader* ret = *first;
    extensionHeaders.erase(first);
    return ret;
}
