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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // Handle waiting ARP Requests
  for (auto& req : m_arpRequests) {
    if (steady_clock::now() - req->timeSent >= seconds(1)) {
      if (req->nTimesSent < 5) {
        // Lookup the next hop
        const RoutingTableEntry route = m_router.getRoutingTable().lookup(req->ip);
        const Interface* next_hop_iface = m_router.findIfaceByName(route.ifName);
        if (next_hop_iface == nullptr) {
          std::cerr << "Unknown next-hop interface '" << route.ifName << "'. Dropping." << std::endl;
          return;
        }
        // Send an ARP Request
        Buffer arp_req_buf(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        // Set the ethernet headers correctly
        ethernet_hdr* req_eth_hdr = (ethernet_hdr*)(arp_req_buf.data());
        std::fill(req_eth_hdr->ether_dhost, req_eth_hdr->ether_dhost + ETHER_ADDR_LEN, 0xFF); // Send to the broadcast address
        memcpy(req_eth_hdr->ether_shost, next_hop_iface->addr.data(), ETHER_ADDR_LEN); // Source is the MAC of the next-hop iface
        req_eth_hdr->ether_type = htons(ethertype_arp);
        // Set the arp headers correctly
        arp_hdr* req_arp_hdr = (arp_hdr*)(arp_req_buf.data() + sizeof(ethernet_hdr));
        req_arp_hdr->arp_hrd = htons(arp_hrd_ethernet);
        req_arp_hdr->arp_pro = htons(0x0800);
        req_arp_hdr->arp_hln = 6;
        req_arp_hdr->arp_pln = 4;
        req_arp_hdr->arp_op = htons(arp_op_request); // Convert opcode to network byte order
        memcpy(req_arp_hdr->arp_sha, next_hop_iface->addr.data(), ETHER_ADDR_LEN); // Source is the MAC of the next-hop iface
        req_arp_hdr->arp_sip = next_hop_iface->ip; // Source is the IP of the next-hop iface
        std::fill(req_arp_hdr->arp_tha, req_arp_hdr->arp_tha + ETHER_ADDR_LEN, 0); // Fill the target MAC with 0s
        req_arp_hdr->arp_tip = route.gw; // Target IP is the gateway
        // Send the packet
        std::cout << "Resending ARP Request for gateway " << ipToString(route.gw) << std::endl;
        print_hdrs(arp_req_buf); ///////////////////////////////////////////////////////
        m_router.sendPacket(arp_req_buf, next_hop_iface->name);
        // Update statistics
        req->timeSent = steady_clock::now();
      }
      req->nTimesSent++;
    }
  }

  // Remove timed-out requests
  //auto req_it = std::remove_if(m_arpRequests.begin(), m_arpRequests.end(), [](const std::shared_ptr<ArpRequest> &entry){ return entry->nTimesSent >= 5; });
  //m_arpRequests.erase(req_it, m_arpRequests.end());
  m_arpRequests.remove_if([](const std::shared_ptr<ArpRequest> &entry){ return entry->nTimesSent > 5; });

  // Remove invalid arp cache entries
  //auto it = std::remove_if(m_cacheEntries.begin(), m_cacheEntries.end(), [](const std::shared_ptr<ArpEntry> &entry){ return !entry->isValid; });
  //m_cacheEntries.erase(it, m_cacheEntries.end());
  m_cacheEntries.remove_if([](const std::shared_ptr<ArpEntry> &entry){ return !entry->isValid; });
}

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueArpRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeArpRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
