/*
Copyright (c) 2017 Erik Rigtorp <erik@rigtorp.se>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include <etherfabric/efct_vi.h>
#include <etherfabric/memreg.h>
#include <etherfabric/pd.h>
#include <etherfabric/vi.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <array>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <pcap.h>
#include <sys/mman.h>
#include <system_error>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <vector>

// Per Solarflare documentation
constexpr size_t pktBufSize = 2048;

// Should be multiple of 8 according to Solarflare documentation
constexpr int refillBatchSize = 16;

constexpr size_t pcapRingCapacity = 8192;
static_assert((pcapRingCapacity & (pcapRingCapacity - 1)) == 0,
              "pcapRingCapacity must be a power of two");

// Huge page size for your platform
#if defined(__x86_64__) || defined(__i386__)
constexpr size_t hugePageSize = 2 * 1024 * 1024;
#endif

struct PcapSlot {
  uint32_t caplen;
  struct timeval ts;
  uint8_t data[pktBufSize];
};

class SpscRing {
public:
  bool try_push(const PcapSlot &slot) {
    const uint32_t tail = tail_.load(std::memory_order_relaxed);
    const uint32_t next = (tail + 1) & (pcapRingCapacity - 1);
    if (next == head_.load(std::memory_order_acquire)) {
      return false;
    }
    slots_[tail] = slot;
    tail_.store(next, std::memory_order_release);
    return true;
  }

  bool try_pop(PcapSlot &slot) {
    const uint32_t head = head_.load(std::memory_order_relaxed);
    if (head == tail_.load(std::memory_order_acquire)) {
      return false;
    }
    slot = slots_[head];
    head_.store((head + 1) & (pcapRingCapacity - 1), std::memory_order_release);
    return true;
  }

  bool empty() const {
    return head_.load(std::memory_order_acquire) ==
           tail_.load(std::memory_order_acquire);
  }

private:
  std::array<PcapSlot, pcapRingCapacity> slots_{};
  alignas(64) std::atomic<uint32_t> head_{0};
  alignas(64) std::atomic<uint32_t> tail_{0};
};

struct WriterContext {
  SpscRing *ring;
  pcap_dumper_t *dumper;
  std::atomic<bool> *running;
};

struct PktBuf {
  int id;
  ef_addr efAddr;
  PktBuf *next;
};

struct Resources {
  ef_driver_handle dh;
  struct ef_pd pd;
  struct ef_vi vi;
  int rxPrefixLen;
  void *pktBufs;
  int nPktBufs;
  struct ef_memreg memreg;
  std::vector<PktBuf> pktBufPool;
  PktBuf *freePktBufs;
  int freePktBufsN;
  int refillLevel;
  int refillMin;
};

static std::ostream &operator<<(std::ostream &os, const in_addr addr) {
  std::array<char, INET_ADDRSTRLEN> str = {};
  inet_ntop(AF_INET, &addr, str.data(), str.size());
  os.write(str.data(), strnlen(str.data(), str.size()));
  return os;
}

static void printPacket(const void *buf, int /*len*/) {
  auto p = reinterpret_cast<const char *>(buf);
  auto eth = reinterpret_cast<const ether_header *>(p);
  if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
    auto ip = reinterpret_cast<const iphdr *>(p + sizeof(ether_header));
    if (ip->version == 4) {
      if (ip->protocol == IPPROTO_TCP) {
        auto tcp = reinterpret_cast<const tcphdr *>(p + sizeof(ether_header) +
                                                    sizeof(iphdr));
        std::cout << "ip tcp from " << in_addr{ip->saddr} << ":"
                  << ntohs(tcp->source) << " to " << in_addr{ip->daddr} << ":"
                  << ntohs(tcp->dest) << std::endl;
      } else if (ip->protocol == IPPROTO_UDP) {
        auto udp = reinterpret_cast<const udphdr *>(p + sizeof(ether_header) +
                                                    sizeof(iphdr));
        std::cout << "ip udp from " << in_addr{ip->saddr} << ":"
                  << ntohs(udp->source) << " to " << in_addr{ip->daddr} << ":"
                  << ntohs(udp->dest) << std::endl;
      } else {
        std::cout << "ip " << ip->protocol << std::endl;
      }
    }
  } else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
    std::cout << "arp" << std::endl;
  } else {
    std::cout << ntohs(eth->ether_type) << std::endl;
  }
}

static void pktBufFree(Resources &res, PktBuf *pktBuf) {
  pktBuf->next = res.freePktBufs;
  res.freePktBufs = pktBuf;
  ++res.freePktBufsN;
}

static PktBuf *pktBufFromId(Resources &res, int id) {
  return &res.pktBufPool[static_cast<size_t>(id)];
}

static bool refillRxRing(Resources &res) {
  if (ef_vi_receive_fill_level(&res.vi) > res.refillLevel ||
      res.freePktBufsN < refillBatchSize) {
    return false;
  }

  do {
    for (int i = 0; i < refillBatchSize; ++i) {
      PktBuf *pktBuf = res.freePktBufs;
      res.freePktBufs = pktBuf->next;
      --res.freePktBufsN;
      ef_vi_receive_init(&res.vi, pktBuf->efAddr, pktBuf->id);
    }
  } while (ef_vi_receive_fill_level(&res.vi) < res.refillMin &&
           res.freePktBufsN >= refillBatchSize);
  ef_vi_receive_push(&res.vi);
  return true;
}

static struct timeval timespecToTimeval(const timespec &ts) {
  struct timeval tv = {};
  tv.tv_sec = ts.tv_sec;
  tv.tv_usec = static_cast<suseconds_t>(ts.tv_nsec / 1000);
  return tv;
}

static struct timeval hwTimestampToTimeval(const timespec &ts) {
  struct timeval tv = {};
  tv.tv_sec = ts.tv_sec;
  tv.tv_usec = static_cast<suseconds_t>(ts.tv_nsec);
  return tv;
}

struct CaptureOutput {
  bool hwTimestamps;
  bool useWriter;
  pcap_dumper_t *pcapDumper;
  SpscRing *ring;
  std::atomic<uint64_t> *droppedEnqueue;
};

struct RxRefGuard {
  struct ef_vi *vi;
  unsigned pktId;

  ~RxRefGuard() { efct_vi_rxpkt_release(vi, pktId); }
};

static int clampCaptureLen(int bufLen) {
  if (bufLen <= 0) {
    return 0;
  }
  if (static_cast<size_t>(bufLen) > pktBufSize) {
    return static_cast<int>(pktBufSize);
  }
  return bufLen;
}

static void deliverPacket(const char *buf, int bufLen, const void *hwPkt,
                          Resources &res, CaptureOutput &out,
                          const timespec *batchTs) {
  const int captureLen = clampCaptureLen(bufLen);
  if (captureLen == 0) {
    return;
  }

  if (out.useWriter) {
    PcapSlot slot = {};
    slot.caplen = static_cast<uint32_t>(captureLen);
    if (out.hwTimestamps) {
      timespec ts = {};
      unsigned flags = 0;
      if (ef_vi_receive_get_timestamp_with_sync_flags(
              &res.vi, hwPkt, &ts, &flags)) {
        throw std::runtime_error("failed to get hw timestamp");
      }
      slot.ts = hwTimestampToTimeval(ts);
    } else {
      slot.ts = timespecToTimeval(*batchTs);
    }
    std::memcpy(slot.data, buf, static_cast<size_t>(captureLen));
    if (!out.ring->try_push(slot)) {
      ++(*out.droppedEnqueue);
    }
    return;
  }

  if (out.pcapDumper) {
    pcap_pkthdr pktHdr = {};
    pktHdr.caplen = static_cast<bpf_u_int32>(captureLen);
    pktHdr.len = static_cast<bpf_u_int32>(bufLen);
    if (out.hwTimestamps) {
      timespec ts = {};
      unsigned flags = 0;
      if (ef_vi_receive_get_timestamp_with_sync_flags(
              &res.vi, hwPkt, &ts, &flags)) {
        throw std::runtime_error("failed to get hw timestamp");
      }
      pktHdr.ts = hwTimestampToTimeval(ts);
    } else {
      pktHdr.ts = timespecToTimeval(*batchTs);
    }
    pcap_dump(reinterpret_cast<u_char *>(out.pcapDumper), &pktHdr,
              reinterpret_cast<const u_char *>(buf));
  } else {
    printPacket(buf, captureLen);
  }
}

static void handleRx(Resources &res, int pktBufId, int len, const void *hwPkt,
                     CaptureOutput &out, const timespec *batchTs) {
  pktBufFree(res, pktBufFromId(res, pktBufId));
  const char *buf = static_cast<const char *>(res.pktBufs) +
                      pktBufSize * pktBufId + res.rxPrefixLen;
  deliverPacket(buf, len, hwPkt, res, out, batchTs);
}

static void handleRxRef(Resources &res, unsigned pktId, int len,
                        CaptureOutput &out, const timespec *batchTs) {
  const void *pkt = efct_vi_rxpkt_get(&res.vi, pktId);
  RxRefGuard guard{&res.vi, pktId};
  const char *buf = static_cast<const char *>(pkt);
  deliverPacket(buf, len, pkt, res, out, batchTs);
}

static void writerThread(WriterContext *ctx) {
  PcapSlot slot;
  while (ctx->running->load(std::memory_order_acquire) || !ctx->ring->empty()) {
    if (ctx->ring->try_pop(slot)) {
      pcap_pkthdr pktHdr = {};
      pktHdr.ts = slot.ts;
      pktHdr.caplen = slot.caplen;
      pktHdr.len = slot.caplen;
      pcap_dump(reinterpret_cast<u_char *>(ctx->dumper), &pktHdr, slot.data);
    } else {
      std::this_thread::yield();
    }
  }
}

std::atomic<bool> active = {true};

extern "C" void signalHandler(int /*signal*/) { active = false; }

int main(int argc, char *argv[]) {
  static const char usage[] =
      " [-i iface] [-w file] [-t] [-o] maddr\n"
      "\n"
      "  -i iface    Interface to capture packets from\n"
      "  -w file     Write packets in pcap format to file\n"
      "  -t          Use hardware timestamps if available (or fail)\n"
      "  -o          Capture outgoing packets if available (or fail)";

  std::string interface;
  std::string filename;
  bool hw_timestamps = false;
  bool sniff_transmit = false;
  int c = 0;
  while ((c = getopt(argc, argv, "i:w:to")) != -1) {
    switch (c) {
    case 'i':
      interface = optarg;
      break;
    case 'w':
      filename = optarg;
      break;
    case 't':
      hw_timestamps = true;
      break;
    case 'o':
      sniff_transmit = true;
      break;
    default:
      std::cerr << "usage: " << argv[0] << usage << std::endl;
      return 1;
    }
  }

  struct Filter {
    in_addr addr;
    in_port_t port;
  };
  std::vector<Filter> filters;
  for (int i = optind; i < argc; i++) {
    Filter filter = {};
    char *sep = strchr(argv[i], ':');
    if (sep) {
      *sep = 0;
      filter.port = htons(atoi(sep + 1));
    }
    if (inet_aton(argv[i], &filter.addr) == 0) {
      throw std::runtime_error("invalid address");
    }
    filters.push_back(filter);
  }

  std::signal(SIGINT, signalHandler);

  Resources res = {};

  if (ef_driver_open(&res.dh) < 0) {
    throw std::system_error(errno, std::generic_category(), "ef_driver_open");
  }
  if (ef_pd_alloc_by_name(&res.pd, res.dh, interface.c_str(), EF_PD_DEFAULT) <
      0) {
    throw std::system_error(errno, std::generic_category(),
                            "ef_pd_alloc_by_name");
  }

  unsigned vi_flags = EF_VI_FLAGS_DEFAULT;
  if (hw_timestamps) {
    vi_flags |= EF_VI_RX_TIMESTAMPS;
  }
  if (ef_vi_alloc_from_pd(&res.vi, res.dh, &res.pd, res.dh, -1, -1, 0, NULL, -1,
                          static_cast<enum ef_vi_flags>(vi_flags)) < 0) {
    throw std::system_error(errno, std::generic_category(),
                            "ef_vi_alloc_from_pd");
  }

  res.rxPrefixLen = ef_vi_receive_prefix_len(&res.vi);

  res.nPktBufs = ef_vi_receive_capacity(&res.vi);
  const size_t bytesNeeded = static_cast<size_t>(res.nPktBufs) * pktBufSize;
  const size_t bytesRounded = (bytesNeeded / hugePageSize + 1) * hugePageSize;
  res.pktBufs = mmap(NULL, bytesRounded, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB, -1, 0);
  if (res.pktBufs == MAP_FAILED) {
    std::cerr << "warning: failed to allocate hugepages for DMA buffers"
              << std::endl;
    if (posix_memalign(&res.pktBufs, 4096, bytesRounded) != 0) {
      throw std::bad_alloc();
    }
  }

  if (ef_memreg_alloc(&res.memreg, res.dh, &res.pd, res.dh, res.pktBufs,
                      bytesRounded) < 0) {
    throw std::system_error(errno, std::generic_category(), "ef_memreg_alloc");
  }

  res.pktBufPool.resize(static_cast<size_t>(res.nPktBufs));
  for (int i = 0; i < res.nPktBufs; ++i) {
    PktBuf &pktBuf = res.pktBufPool[static_cast<size_t>(i)];
    pktBuf.id = i;
    pktBuf.efAddr = ef_memreg_dma_addr(&res.memreg, i * pktBufSize);
    pktBufFree(res, &pktBuf);
  }

  res.refillLevel = res.nPktBufs - refillBatchSize;
  res.refillMin = res.nPktBufs / 2;
  while (ef_vi_receive_fill_level(&res.vi) <= res.refillLevel) {
    refillRxRing(res);
  }

  for (auto filter : filters) {
    ef_filter_spec filter_spec;
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    if (filter.port == 0) {
      uint8_t mac[6] = {0x01,
                        0x00,
                        0x5e,
                        uint8_t(filter.addr.s_addr >> 8 & 0x7f),
                        uint8_t(filter.addr.s_addr >> 16 & 0xff),
                        uint8_t(filter.addr.s_addr >> 24 & 0xff)};
      if (ef_filter_spec_set_eth_local(&filter_spec, EF_FILTER_VLAN_ID_ANY,
                                       mac) < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "ef_filter_spec_set_eth_local");
      }
    } else {
      if (ef_filter_spec_set_ip4_local(&filter_spec, IPPROTO_UDP,
                                       filter.addr.s_addr, filter.port) < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "ef_filter_spec_set_ip4_local");
      }
    }
    if (ef_vi_filter_add(&res.vi, res.dh, &filter_spec, NULL) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_vi_filter_add");
    }
  }
  if (filters.empty()) {
    ef_filter_spec filter_spec;
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    if (ef_filter_spec_set_port_sniff(&filter_spec, 1) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_filter_spec_set_port_sniff");
    }
    if (ef_vi_filter_add(&res.vi, res.dh, &filter_spec, NULL) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_vi_filter_add");
    }
  }
  if (sniff_transmit) {
    ef_filter_spec filter_spec;
    ef_filter_spec_init(&filter_spec, EF_FILTER_FLAG_NONE);
    if (ef_filter_spec_set_tx_port_sniff(&filter_spec)) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_filter_spec_set_tx_port_sniff");
    }
    if (ef_vi_filter_add(&res.vi, res.dh, &filter_spec, NULL) < 0) {
      throw std::system_error(errno, std::generic_category(),
                              "ef_filter_spec_set_tx_port_sniff/ef_vi_filter_add");
    }
  }

  pcap_t *pcap = nullptr;
  pcap_dumper_t *pcapDumper = nullptr;
  SpscRing pcapRing;
  std::thread writer;
  WriterContext writerCtx = {};
  std::atomic<uint64_t> droppedEnqueue = {0};
  const bool useWriter = !filename.empty();

  if (useWriter) {
    int link_type = DLT_EN10MB;
    int snap_len = 65535;
    u_int precision = PCAP_TSTAMP_PRECISION_MICRO;
    if (hw_timestamps) {
      precision = PCAP_TSTAMP_PRECISION_NANO;
    }
    pcap = pcap_open_dead_with_tstamp_precision(link_type, snap_len, precision);
    pcapDumper = pcap_dump_open(pcap, filename.c_str());
    if (!pcapDumper) {
      throw std::runtime_error("pcap_dump_open: " +
                               std::string(pcap_geterr(pcap)));
    }
    writerCtx.ring = &pcapRing;
    writerCtx.dumper = pcapDumper;
    writerCtx.running = &active;
    writer = std::thread(writerThread, &writerCtx);
  }

  CaptureOutput out = {};
  out.hwTimestamps = hw_timestamps;
  out.useWriter = useWriter;
  out.pcapDumper = pcapDumper;
  out.ring = &pcapRing;
  out.droppedEnqueue = &droppedEnqueue;

  std::array<ef_event, 32> evs = {};
  while (active.load(std::memory_order_acquire)) {
    refillRxRing(res);
    const int nev = ef_eventq_poll(&res.vi, evs.data(), evs.size());
    if (nev > 0) {
      timespec batchTs = {};
      if (!hw_timestamps) {
        clock_gettime(CLOCK_REALTIME_COARSE, &batchTs);
      }
      for (int i = 0; i < nev; ++i) {
        switch (EF_EVENT_TYPE(evs[i])) {
        case EF_EVENT_TYPE_RX: {
          if (EF_EVENT_RX_SOP(evs[i]) == 0 || EF_EVENT_RX_CONT(evs[i]) != 0) {
            pktBufFree(res, pktBufFromId(res, EF_EVENT_RX_RQ_ID(evs[i])));
            break;
          }
          const int pktBufId = EF_EVENT_RX_RQ_ID(evs[i]);
          const int len = EF_EVENT_RX_BYTES(evs[i]) - res.rxPrefixLen;
          const void *hwPkt =
              static_cast<const char *>(res.pktBufs) + pktBufSize * pktBufId;
          handleRx(res, pktBufId, len, hwPkt, out, &batchTs);
          break;
        }
        case EF_EVENT_TYPE_RX_DISCARD: {
          pktBufFree(res, pktBufFromId(res, EF_EVENT_RX_DISCARD_RQ_ID(evs[i])));
          break;
        }
        case EF_EVENT_TYPE_RX_REF:
          handleRxRef(res, evs[i].rx_ref.pkt_id, evs[i].rx_ref.len, out,
                      &batchTs);
          break;
        case EF_EVENT_TYPE_RX_REF_DISCARD:
          handleRxRef(res, evs[i].rx_ref_discard.pkt_id,
                      evs[i].rx_ref_discard.len, out, &batchTs);
          break;
        case EF_EVENT_TYPE_RESET:
          throw std::runtime_error("NIC reset: VI is no longer valid");
        default:
          throw std::runtime_error("ef_eventq_poll: unknown event type");
        }
      }
      refillRxRing(res);
    }
  }

  if (useWriter) {
    if (writer.joinable()) {
      writer.join();
    }
    if (droppedEnqueue.load() > 0) {
      std::cerr << "warning: dropped " << droppedEnqueue.load()
                << " packets because pcap queue was full" << std::endl;
    }
    pcap_dump_close(pcapDumper);
    pcap_close(pcap);
  }

  return 0;
}
