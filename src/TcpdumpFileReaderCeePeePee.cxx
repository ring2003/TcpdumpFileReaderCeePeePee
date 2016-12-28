// PacketParser++.cpp : Defines the entry point for the console application.
//
#include <iostream>
#include <RawPacket.h>
#include <Packet.h>
#include <IPv4Layer.h>
#include <PcapFileDevice.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <functional>
#ifdef __linux__
	#include <arpa/inet.h>
#endif

using namespace std;
using namespace pcpp;

void nextHandler(string localAddr, Packet& parsedPacket, std::function<void(const char*, const char*, const char*, const char*, short unsigned int, short unsigned int)> cb)
{
	std::string protoType;
	if (!parsedPacket.isPacketOfType(IPv4))
	{
		return;
	}
	if (parsedPacket.isPacketOfType(ICMP))
	{
		protoType = "ICMP";
	}
	else if (parsedPacket.isPacketOfType(ARP))
	{
		protoType = "ARP";
	}
	else if (parsedPacket.isPacketOfType(VLAN))
	{
		protoType = "VLAN";
	}
	else if (parsedPacket.isPacketOfType(MPLS))
	{
		protoType = "MPLS";
	}
	else if (parsedPacket.isPacketOfType(PPPoE))
	{
		protoType = "PPPoE";
	}
	else if (parsedPacket.isPacketOfType(GRE))
	{
		protoType = "GRE";
	}
	else if (parsedPacket.isPacketOfType(DHCP))
	{
		protoType = "DHCP";
	}
	else if (parsedPacket.isPacketOfType(NULL_LOOPBACK))
	{
		protoType = "LOOPBACK";
	}
	else if (parsedPacket.isPacketOfType(ICMP))
	{
		protoType = "ICMP";
	}
	else
	{
		return;
	}
	IPv4Address src = parsedPacket.getLayerOfType<IPv4Layer>()->getSrcIpAddress();
	IPv4Address dst = parsedPacket.getLayerOfType<IPv4Layer>()->getDstIpAddress();
	cb(protoType.c_str(), localAddr.c_str(), src.toString().c_str(), dst.toString().c_str(), 0, 0);
}

int main(int argc, char* argv[])
{
	if (argc < 3)
	{
		cerr << "Usage: ./program localIpAddress /path/to/tcpdump.pcap" << endl;
		return -1;
	}
	string localAddr(argv[1]);
	const char* pcapFile(argv[2]);

	PcapFileReaderDevice reader(pcapFile);

	function<void(const char*, const char*, const char*, const char*, uint16_t, uint16_t)> formatter =
			[](const char* proto, const char* localAddr, const char* srcAddr, const char* dstAddr, uint16_t srcPort, uint16_t dstPort) {
				cout << localAddr << " ";
				cout << srcAddr << " ";
				cout << dstAddr << " ";
				cout << srcPort << " ";
				cout << dstPort << " ";
				cout << proto << " " << "->" << '\n';
		};

	if (!reader.open())
	{
		cerr << "Open tcpdump file '" << pcapFile << "' failed." << endl;
		return -1;
	}

	while (true)
	{
		RawPacket rawp;

		if (!reader.getNextPacket(rawp))
		{
			break;
		}

		Packet parsedPacket(&rawp);
		std::string protoType;
		uint16_t portsrc = 0;
		uint16_t portdst = 0;

		if (parsedPacket.isPacketOfType(TCP))
		{
			protoType = "TCP";
			tcphdr* tcpheader = parsedPacket.getLayerOfType<TcpLayer>()->getTcpHeader();
			portsrc = tcpheader->portSrc;
			portdst = tcpheader->portDst;
		}
		else if (parsedPacket.isPacketOfType(UDP))
		{
			protoType = "UDP";
			udphdr* udpheader = parsedPacket.getLayerOfType<UdpLayer>()->getUdpHeader();
			portsrc = udpheader->portSrc;
			portdst = udpheader->portDst;
		}
		else
		{
			nextHandler(localAddr, parsedPacket, formatter);
			continue;
		}
		if (parsedPacket.isPacketOfType(HTTP))
		{
			protoType = "HTTP";
		}
		else if (parsedPacket.isPacketOfType(DNS))
		{
			protoType = "DNS";
		}
		else if (parsedPacket.isPacketOfType(SSL))
		{
			protoType = "SSL";
		}
		else
		{
			;
		}

		if (parsedPacket.isPacketOfType(IPv4))
		{
			IPv4Address src = parsedPacket.getLayerOfType<IPv4Layer>()->getSrcIpAddress();
			IPv4Address dst = parsedPacket.getLayerOfType<IPv4Layer>()->getDstIpAddress();
			formatter(protoType.c_str(), localAddr.c_str(), src.toString().c_str(), dst.toString().c_str(),  ntohs(portsrc),  ntohs(portdst));
		}
	}
	reader.close();
	return 0;
}

