/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <memory>

namespace simple_router {

void
SimpleRouter::processPacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  //std::cerr << getRoutingTable() << std::endl;

  // Check Eth frame destination address. If not for this iface or broadcast, drop
  //print_hdr_eth(packet.data());
  const ethernet_hdr* eth_hdrs = (const ethernet_hdr*)packet.data();
  const uint64_t BROADCAST_ADDR = 0xFFFFFFFFFFFFFFFF;

  if (!std::equal(eth_hdrs->ether_dhost, eth_hdrs->ether_dhost + ETHER_ADDR_LEN, (uint8_t*)&BROADCAST_ADDR) && 
    !(iface->addr.size() == ETHER_ADDR_LEN && std::equal(eth_hdrs->ether_dhost, eth_hdrs->ether_dhost + ETHER_ADDR_LEN, iface->addr.data()))) {
      std::cout << "Dropping packet for non-broadcast MAC." << std::endl;
      return;
  }

  uint16_t type = ntohs(eth_hdrs->ether_type); // Convert type from network byte order
  if (type == ethertype_arp) {
    const arp_hdr* arp_hdrs = (const arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
    // Check that this ARP packet is for IP->Eth
    if (ntohs(arp_hdrs->arp_hrd) != arp_hrd_ethernet) {
      std::cerr << "ARP hardware address format not Ethernet. Dropping." << std::endl;
      return;
    }
    if (arp_hdrs->arp_hln != ETHER_ADDR_LEN) {
      std::cerr << "ARP hardware address length not correct for Ethernet. Expected: 6 but got: " << arp_hdrs->arp_hln << ". Dropping." << std::endl;
      return;
    }
    if (ntohs(arp_hdrs->arp_pro) != 0x0800) {
      std::cerr << "ARP protocol address format not IPv4. Dropping." << std::endl;
      return;
    }
    if (arp_hdrs->arp_pln != 4) {
      std::cerr << "ARP protocol address length not correct for IPv4. Expected: 4 but got: " << arp_hdrs->arp_pln << ". Dropping." << std::endl;
      return;
    }
    uint16_t opcode = ntohs(arp_hdrs->arp_op);
    if (opcode == arp_op_request) {
      // If ARP Request, drop UNLESS it's for this interface, in which case respond
      uint32_t destip = arp_hdrs->arp_tip;
      if (destip != iface->ip) {
        std::cout << "Dropping ARP request for " << ipToString(destip) << ", my IP is " << ipToString(iface->ip) << std::endl;
        return;
      } else {
        // Respond with an ARP reply
        Buffer reply_buf(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        memcpy(reply_buf.data(), packet.data(), reply_buf.size()); // Start by copying the Request packet (for ARP headers)
        // Set the ethernet headers correctly
        ethernet_hdr* reply_eth_hdr = (ethernet_hdr*)(reply_buf.data());
        memcpy(reply_eth_hdr->ether_dhost, arp_hdrs->arp_sha, ETHER_ADDR_LEN); // Reply to the source hadware address of the ARP Request
        memcpy(reply_eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN); // Source is the MAC of this iface
        // Set the arp headers correctly
        arp_hdr* reply_arp_hdr = (arp_hdr*)(reply_buf.data() + sizeof(ethernet_hdr));
        reply_arp_hdr->arp_op = htons(arp_op_reply); // Convert opcode to network byte order
        memcpy(reply_arp_hdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN); // Source is the MAC of this iface
        reply_arp_hdr->arp_sip = iface->ip; // Source is the IP of this iface
        memcpy(reply_arp_hdr->arp_tha, arp_hdrs->arp_sha, ETHER_ADDR_LEN);
        reply_arp_hdr->arp_tip = arp_hdrs->arp_sip;
        // Send the packet
        std::cout << "Sending ARP Reply to " << ipToString(arp_hdrs->arp_sip) << std::endl;
        sendPacket(reply_buf, iface->name);
        return;
      }
    } else if (opcode == arp_op_reply) {
      // If ARP Reply, cache translation
      Buffer reply_mac(arp_hdrs->arp_sha, arp_hdrs->arp_sha + ETHER_ADDR_LEN);
      std::shared_ptr<ArpRequest> waiting_packets = m_arp.insertArpEntry(reply_mac, arp_hdrs->arp_sip);
      std::cout << "Got ARP Reply from " << ipToString(arp_hdrs->arp_sip) << std::endl;
      // Send packets waiting on Reply
      if (waiting_packets.get() != nullptr) {
        for (auto& packet : waiting_packets->packets) {
          ethernet_hdr* waiting_hdr = (ethernet_hdr*)packet.packet.data();
          memcpy(waiting_hdr->ether_dhost, arp_hdrs->arp_sha, ETHER_ADDR_LEN);
          std::cout << "Forwarding waiting packet on interface '" << packet.iface << "'" << std::endl;
          sendPacket(packet.packet, packet.iface);
        }
        // Free the packet from the request queue
        m_arp.removeArpRequest(waiting_packets);
      }
    }
  } else if (type == ethertype_ip) {
    // Verify minimum packet length
    size_t packet_length = packet.size() - sizeof(ethernet_hdr);
    if (packet_length < sizeof(ip_hdr)) {
      std::cerr << "IPv4 minimum length violated: expected: " << sizeof(ip_hdr) << " but got: " << packet_length << ". Dropping." << std::endl;
      return;
    }
    // Verify IPv4 checksum
    const ip_hdr* ip_hdrs = (const ip_hdr*)(packet.data() + sizeof(ethernet_hdr));
    ip_hdr cksum_buf;
    memcpy(&cksum_buf, ip_hdrs, sizeof(ip_hdr));
    cksum_buf.ip_sum = 0;
    uint16_t calc_cksum = cksum(&cksum_buf, sizeof(ip_hdr));
    if (calc_cksum != ip_hdrs->ip_sum) {
      std::cerr << "Checksum mismatch: expected: " << ip_hdrs->ip_sum << " but calculated: " << calc_cksum << ". Dropping." << std::endl;
      return;
    }
    // If dest address is any of the interfaces on the router, drop packet
    const Interface* dest_iface = findIfaceByIp(ip_hdrs->ip_dst);
    if (dest_iface != nullptr) {
      std::cout << "Dropping packet addressed to interface '" << dest_iface->name << "' (" << ipToString(dest_iface->ip) << ")." << std::endl;
      return;
    }
    // If TTL is expired, drop packet
    if (ip_hdrs->ip_ttl == 0 || ip_hdrs->ip_ttl == 1) {
      std::cerr << "TTL Expired. Dropping." << std::endl;
      return;
    }
    // Check ACL for applicable rules
    uint16_t src_port = 0, dst_port = 0;
    if (ip_hdrs->ip_p == ip_protocol_tcp || ip_hdrs->ip_p == ip_protocol_udp) {
      // If UDP or TCP, set ports based on headers. Assume port is 0 for all other protocol types.
      const uint16_t* proto_hdrs = (const uint16_t*)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
      src_port = ntohs(*proto_hdrs);
      proto_hdrs++;
      dst_port = ntohs(*proto_hdrs);
    }
    try {
      ACLTableEntry entry = m_aclTable.lookup(ntohl(ip_hdrs->ip_src), ntohl(ip_hdrs->ip_dst), ip_hdrs->ip_p, src_port, dst_port);
      if (entry.action == "deny" || entry.action == "DENY" || entry.action == "Deny") {
        // Log the rule
        std::cout << "Denying: " << entry;
        m_aclLogFile << entry;
        return;
      } else if (entry.action == "permit" || entry.action == "PERMIT" || entry.action == "Permit") {
        // Fall through and forward the packet
        std::cout << "Permitting: " << entry;
        m_aclLogFile << entry;
      } else {
        // Fall through and forward the packet, but write out a complaint
        std::cout << "Unknown action '" << entry.action << "'. Permitting." << std::endl;
        std::cout << entry;
      }
    }
    catch (const std::runtime_error& error) {
      // A runtime error here means no ACL entry was found, so default to allow
      //std::cout << "No ACL entry found. Permitting." << std::endl;
    }
    // Look up interface to forward on
    const RoutingTableEntry route = m_routingTable.lookup(ip_hdrs->ip_dst);
    const Interface* fwd_iface = findIfaceByName(route.ifName);
    if (fwd_iface == nullptr) {
      std::cerr << "Unknown forwarding interface '" << route.ifName << "'. Dropping." << std::endl;
      return;
    }
    // Ensure that forwarding iface has an address of length ETHER_ADDR_LEN
    if (fwd_iface->addr.size() != ETHER_ADDR_LEN) {
      std::cerr << "Forwarding interface address length not correct for Ethernet. Expected: 6 but got: " << fwd_iface->addr.size() << ". Dropping." << std::endl;
      return;
    }
    // Construct a new packet to forward
    Buffer fwd_buf(packet); // Start by copying the IP packet using the copy constructor
    // Set the ethernet headers correctly
    ethernet_hdr* fwd_eth_hdr = (ethernet_hdr*)(fwd_buf.data());
    std::fill(fwd_eth_hdr->ether_dhost, fwd_eth_hdr->ether_dhost + ETHER_ADDR_LEN, 0); // Blank next hop MAC until we check the ARP cache
    memcpy(fwd_eth_hdr->ether_shost, fwd_iface->addr.data(), ETHER_ADDR_LEN); // Source is the MAC of the forwarding iface
    // Set the ip headers correctly
    ip_hdr* fwd_ip_hdr = (ip_hdr*)(fwd_buf.data() + sizeof(ethernet_hdr));
    fwd_ip_hdr->ip_ttl--; // Decrement the TTL by one
    fwd_ip_hdr->ip_sum = 0;
    fwd_ip_hdr->ip_sum = cksum(fwd_ip_hdr, sizeof(ip_hdr)); // Calculate a new checksum

    std::shared_ptr<ArpEntry> next_hop = m_arp.lookup(route.gw);
    if (next_hop == nullptr) {
      // Gateway MAC unknown, send an ARP request for the next hop
      // First cache the IP packet for later resending
      std::shared_ptr<ArpRequest> queued_arp = m_arp.queueArpRequest(route.gw, fwd_buf, route.ifName);
      if (queued_arp->nTimesSent == 0) {
        // This is a new request, so send an ARP request immediately
        queued_arp->timeSent = steady_clock::now();
        queued_arp->nTimesSent = 1;
        Buffer arp_req_buf(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        // Set the ethernet headers correctly
        ethernet_hdr* req_eth_hdr = (ethernet_hdr*)(arp_req_buf.data());
        memcpy(req_eth_hdr->ether_dhost, (uint8_t*)&BROADCAST_ADDR, ETHER_ADDR_LEN); // Send to the broadcast address
        memcpy(req_eth_hdr->ether_shost, fwd_iface->addr.data(), ETHER_ADDR_LEN); // Source is the MAC of the forwarding iface
        req_eth_hdr->ether_type = htons(ethertype_arp);
        // Set the arp headers correctly
        arp_hdr* req_arp_hdr = (arp_hdr*)(arp_req_buf.data() + sizeof(ethernet_hdr));
        req_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
        req_arp_hdr->arp_pro = htons(0x0800);
        req_arp_hdr->arp_hln = 6;
        req_arp_hdr->arp_pln = 4;
        req_arp_hdr->arp_op = htons(arp_op_request); // Convert opcode to network byte order
        memcpy(req_arp_hdr->arp_sha, fwd_iface->addr.data(), ETHER_ADDR_LEN); // Source is the MAC of the forwarding iface
        req_arp_hdr->arp_sip = fwd_iface->ip; // Source is the IP of the forwarding iface
        std::fill(req_arp_hdr->arp_tha, req_arp_hdr->arp_tha + ETHER_ADDR_LEN, 0); // Fill the target MAC with 0s
        req_arp_hdr->arp_tip = route.gw; // Target IP is the gateway
        // Send the packet
        std::cout << "Sending ARP Request for gateway " << ipToString(route.gw) << std::endl;
        sendPacket(arp_req_buf, fwd_iface->name);
      }
      return;
    } else {
      // Forward the packet
      memcpy(fwd_eth_hdr->ether_dhost, next_hop->mac.data(), ETHER_ADDR_LEN);
      std::cout << "Forwarding a packet to " << ipToString(fwd_ip_hdr->ip_dst) << std::endl; 
      sendPacket(fwd_buf, fwd_iface->name);
      return;
    }
  } else {
    std::cerr << "Unrecognized ethernet type " << type << ". Dropping." << std::endl;
    return;
  }

  // Unresolved question: Should we ARP for a non-existent host on another subnet? Or send to the "gateway" on that subnet?
  // Without a subnet mask given for each interface, I believe that the only reasonable course of action (and the one the spec
  // supports) is to forward to the gateway. We can't know whether the destination is on the subnet without a subnet mask.

}

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
  m_aclLogFile.open("router-acl.log");
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

bool
SimpleRouter::loadACLTable(const std::string& aclConfig)
{
  return m_aclTable.load(aclConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
