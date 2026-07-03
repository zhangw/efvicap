# efvicap: Usage and Limitations

This document describes practical considerations for operating **efvicap** and other tools built on AMD/Xilinx Solarflare **ef_vi** port sniffing. It is written from the vendor API and firmware perspective (Onload, etherfabric, SolarCapture) and applies to any deployment using hardware port sniff—not a specific environment.

**efvicap** is a minimal ef_vi-based capture utility. It opens a Protection Domain (PD) on a physical NIC, allocates a Virtual Interface (VI), installs port-sniff filters, and delivers matched frames to stdout or a pcap file. Optional transmit (TX) port sniff mirrors egress traffic from the adapter.

---

## Prerequisites

| Requirement | Purpose |
|-------------|---------|
| **Solarflare/Xilinx network adapter** | Port sniff is implemented in NIC firmware via MCDI; not available on generic NICs |
| **sfc / Onload driver stack** | Provides `/dev/sfc_char`, MCDI, and the **etherfabric** (`libciul`) userspace library |
| **Onload or OpenOnload installation** | Headers and libraries: `etherfabric/vi.h`, `etherfabric/pd.h`, `etherfabric/efct_vi.h` |
| **`CAP_NET_ADMIN` (or root)** | Required to allocate PDs, configure filters, and enable port sniff MCDI commands |
| **SolarCapture Pro license (typical)** | RX and TX port sniff are licensed features; unlicensed adapters reject sniff configuration |

### Driver and library checks

```sh
# Driver loaded
lsmod | grep sfc
# or
onload_tool version

# Character device present
ls -l /dev/sfc_char

# License state (feature bits vary by product)
onload_tool license
```

If `ef_driver_open()` fails with `ENOENT` or `EACCES`, the sfc driver is not loaded or the process lacks permission to open `/dev/sfc_char`.

### Licensing (overview)

Port sniff is gated by **LICENSED_V3** feature bits in adapter license data:

| Feature bit | Capability |
|-------------|------------|
| **RX_SNIFF** | Receive (ingress) port sniff—mirror frames arriving at the port |
| **TX_SNIFF** | Transmit (egress) port sniff—mirror frames transmitted by the port |

**SolarCapture Pro** (and equivalent enterprise licenses) typically include both bits. **SolarCapture Plus** and base Onload licenses often include neither or only partial capture features. Without the appropriate bit, `ef_filter_spec_set_port_sniff()` or `ef_filter_spec_set_tx_port_sniff()` followed by `ef_vi_filter_add()` fails at the driver/firmware boundary—commonly `EPERM`, `EOPNOTSUPP`, or a vendor-specific MCDI error mapped to errno.

See [License](#licensing-rx_sniff-vs-tx_sniff) below for detail.

---

## efvicap CLI Reference

```
usage: efvicap [-i iface] [-w file] [-t] [-o] [filters...]

  -i iface    Physical interface name (e.g. eth2, sfc1)
  -w file     Write captured packets in pcap format to file (- for stdout pipe)
  -t          Require hardware RX timestamps (nanosecond precision in pcap)
  -o          Enable TX port sniff (capture outgoing traffic; fail if unsupported)
  filters     Optional IP or IP:port filters (multicast/UDP); omit for all traffic
```

### Examples

```sh
# Print decoded summaries of all RX (and optionally TX) port-sniffed frames
efvicap -i eth2

# Save full frames to pcap
efvicap -i eth2 -w capture.pcap

# Pipe to tcpdump for display/filtering
efvicap -i eth2 -w - | tcpdump -r - -n

# Filter to specific multicast groups / UDP ports
efvicap -i eth2 -w out.pcap 230.0.0.1:5000 230.0.0.2:6000

# RX + TX sniff with hardware timestamps
efvicap -i eth2 -o -t -w full.pcap
```

When no positional filters are given, efvicap installs a default **RX port sniff** filter (`ef_filter_spec_set_port_sniff`). With `-o`, it additionally installs **TX port sniff** (`ef_filter_spec_set_tx_port_sniff`).

**Note:** efvicap does not expose a separate promiscuous-mode flag. Port sniff behavior (what traffic is mirrored) is determined by the firmware sniff mode and filter spec, not by `IFF_PROMISC` on a kernel netdevice.

---

## Interface Naming and VLANs

### Physical interfaces only for `ef_pd_alloc_by_name`

efvicap (and most sample code) calls:

```c
ef_pd_alloc_by_name(&pd, dh, interface_name, EF_PD_DEFAULT);
```

This API accepts **physical Solarflare port names** as reported by the driver—e.g. `eth2`, `sfc0`, `ens1f0`—matching the name in `/sys/class/net/` for the underlying PCI function.

It does **not** accept Linux VLAN subinterface names such as:

- `sfc1.1609`
- `sfc1.1609@sfc1` (vlan protocol naming)
- `vlan1609`

Attempting PD allocation on a VLAN netdev typically fails with `ENODEV` or `EINVAL` because there is no independent ef_vi PD bound to a kernel VLAN device.

### VLAN traffic requires `ef_pd_alloc_with_vport`

To sniff traffic on a specific **802.1Q VLAN**, applications must:

1. Allocate the PD on the **physical port** (or use `ef_pd_alloc_with_vport()` with an explicit virtual port ID).
2. Set the VLAN ID in filter specifications, e.g. `ef_filter_spec_set_eth_local(..., vlan_id, mac)` or equivalent VLAN-aware sniff configuration per **Onload Programmer's Guide** / **SolarCapture API** documentation.

efvicap currently has no `-V vlan_id` option; capturing VLAN-tagged traffic with correct filtering requires extending the tool or using **SolarCapture** with explicit vport/VLAN configuration.

| Symptom | Cause | Remediation |
|---------|-------|-------------|
| `ef_pd_alloc_by_name: No such device` on `sfc1.100` | VLAN subinterface is not a valid PD target | Use physical interface name; add VLAN ID to ef_filter_spec |
| Sniff sees untagged traffic only | Filters/default sniff on physical port without VLAN match | Use `EF_FILTER_VLAN_ID_ANY` or specific VLAN in filter spec |
| Wrong traffic mix | Multiple VLANs on same port | Allocate vport per VLAN or filter by VLAN ID |

---

## RX Port Sniff vs TX Port Sniff

Port sniff on Solarflare adapters is implemented as **firmware-mediated mirroring** of frames on a physical port into an ef_vi RX queue. RX and TX sniff use **different MCDI commands** and **different license bits**.

| Aspect | RX port sniff | TX port sniff |
|--------|---------------|---------------|
| MCDI | `MC_CMD_SET_PORT_SNIFF_CONFIG` (RX enable) | `MC_CMD_SET_TX_PORT_SNIFF_CONFIG` |
| API | `ef_filter_spec_set_port_sniff()` | `ef_filter_spec_set_tx_port_sniff()` |
| License bit | **RX_SNIFF** | **TX_SNIFF** |
| Traffic mirrored | Frames received on the wire toward the host | Frames transmitted by the adapter (including kernel-bypass / Onload paths) |
| Typical default | Supported on many licensed adapters | Requires **full-featured firmware** |

### ULL / low-latency firmware limitation

**SolarCapture User Guide §4.4** (and related firmware release notes) document that **Ultra-Low Latency (ULL)** and certain cut-down firmware images **exclude transmit port sniff**. On these images:

- RX port sniff may work if licensed.
- TX port sniff returns **`EOPNOTSUPP` (-95)** from the MCDI layer when enabling `MC_CMD_SET_TX_PORT_SNIFF_CONFIG`.

This is a **firmware product choice**, not an application bug. Adapters running ULL firmware target minimum TX latency and omit egress mirroring hardware paths.

| Symptom | Likely cause | Remediation |
|---------|--------------|-------------|
| RX works, `-o` fails with `Operation not supported` | ULL or TX-sniff-disabled firmware | Use full firmware, or external egress capture (see [Alternatives](#alternatives-when-tx-sniff-is-unavailable)) |
| Both RX and TX fail immediately | Missing SolarCapture Pro / sniff license | Install valid license; verify `RX_SNIFF` / `TX_SNIFF` bits |
| TX fails only on one port | Per-port license or firmware variant | Check `onload_tool license` and per-port firmware profile |

---

## Understanding `EOPNOTSUPP` (-95) on TX Sniff

When efvicap is run with `-o`, failure often surfaces as:

```
ef_filter_spec_set_tx_port_sniff/ef_vi_filter_add: Operation not supported
```

(errno **95**, `EOPNOTSUPP`)

### Firmware rejection (most common on ULL)

The driver forwarded `MC_CMD_SET_TX_PORT_SNIFF_CONFIG` to firmware; firmware replied that the operation is not supported on this NIC image. Causes include:

- ULL / performance firmware without TX sniff
- Missing **TX_SNIFF** license bit
- Adapter generation or port mode that never implemented TX sniff

**This is expected behavior.** The application correctly requested TX sniff; the platform cannot provide it.

### Distinguish from efct / X3 missing operations

Newer **efct** (EF_VI over CTPIO) and **X3** code paths may return `EOPNOTSUPP` or **`ENOSYS`** for APIs not yet implemented on that driver variant—distinct from firmware license/firmware-sku rejection.

| Error context | Interpretation |
|---------------|----------------|
| `-o` + `ef_filter_spec_set_tx_port_sniff` → `EOPNOTSUPP` | Almost always firmware/license TX sniff unavailable |
| `ef_vi_capabilities_get()` → `ENOSYS` | Capability query not implemented; unrelated to TX sniff setup |
| `ef_driver_open` / PD alloc fails | Driver or interface naming issue, not sniff-specific |
| Works on RX-only without `-o` | Confirms VI path is fine; TX path specifically blocked |

Do not treat `EOPNOTSUPP` on TX sniff as a bug in efvicap filter ordering or ef_vi allocation when RX sniff succeeds on the same VI.

---

## Single Sniff Owner per Port (`EBUSY`)

Solarflare firmware allows **only one active port sniff consumer per physical port** (RX sniff owner). If a second process (second efvicap, SolarCapture instance, or another ef_vi client) attempts to enable port sniff on the same port:

- `ef_vi_filter_add()` with port sniff may fail with **`EBUSY`**
- Or the first owner's sniff may be implicitly exclusive per `MC_CMD_SET_PORT_SNIFF_CONFIG` semantics

| Symptom | Cause | Remediation |
|---------|-------|-------------|
| `ef_vi_filter_add: Device or resource busy` | Another process already owns RX port sniff on this port | Stop the other capture tool; ensure single sniff instance |
| Intermittent missing packets | Two tools competing (undefined) | Coordinate capture centrally (one SolarCapture hub or one efvicap) |
| Sniff stops when second tool exits | Exclusive ownership handoff | Design for one long-lived capture owner |

TX sniff ownership rules are similar: only one TX sniff configuration per port in typical firmware builds.

---

## Kernel Capture vs Hardware Port Sniff (Onload / TCPDirect)

**tcpdump**, **libpcap** on kernel interfaces, and **AF_PACKET** sockets observe traffic that traverses the **Linux networking stack**. Applications using **OpenOnload**, **Onload**, **TCPDirect**, or **ef_vi** kernel bypass transmit and receive on a **user-space path** that does not copy packets through the kernel stack.

Consequences:

| Capture method | Sees wire ingress to other hosts | Sees traffic to Onload-accelerated local apps | Sees egress from bypass TX |
|----------------|----------------------------------|-------------------------------------------------|----------------------------|
| tcpdump on `ethX` | Yes (with stack delivery) | **No** for fully accelerated RX | **No** for bypass TX |
| RX **port sniff** (ef_vi) | Yes (mirrored at NIC) | **Yes**—mirrored before/alongside stack bypass | N/A |
| TX **port sniff** (ef_vi) | N/A | N/A | **Yes**—mirrors adapter egress |

To debug latency-sensitive or kernel-bypass workloads, **hardware port sniff** (efvicap, SolarCapture, custom ef_vi) is required. Kernel capture alone will show an incomplete picture and may falsely suggest "no traffic" when the application is actively trading over Onload.

---

## RX Sniff Semantics: Wire Traffic, Promiscuous vs Non-Promiscuous

**RX port sniff** mirrors frames received on the **physical port** into the sniff VI. Key points:

1. **Wire-oriented:** Sniff sees what the MAC receives on the cable/fabric port (subject to firmware filtering rules), not merely what the kernel accepted.
2. **Independent of `tcpdump -p`:** efvicap does not toggle kernel promiscuous mode (`IFF_PROMISC`). Sniff is an NIC feature.
3. **Promiscuous-like behavior:** With default port sniff (no MAC/IP filters), many firmware builds deliver **broad ingress mirroring**—functionally similar to promiscuous capture for that port—including unicast not destined for the host, depending on adapter mode and **SolarCapture** sniff configuration.
4. **Filtered sniff:** When filters are installed (efvicap positional filters or explicit `ef_filter_spec`), only matching frames are delivered—analogous to non-promiscuous, selective capture.
5. **Not a replacement for SPAN analytics:** Sniff mirrors to a CPU VI; it does not change forwarding or switching behavior elsewhere.

For multicast-only tools, efvicap's optional `IP` or `IP:port` filters map to `ef_filter_spec_set_eth_local` (multicast MAC derived from IP) or `ef_filter_spec_set_ip4_local` for UDP.

---

## 802.1Q VLAN Tags and stdout Parsing

Sniffed frames often arrive **with 802.1Q tags intact** (4-byte VLAN header between Ethernet addresses and ethertype).

efvicap's default **stdout** path parses a conventional Ethernet header and checks `ether_type` immediately after 14 bytes:

- If a VLAN tag is present, the bytes at offset 12–13 are **`0x8100`** (VLAN TPID), not `0x0800` (IPv4).
- The IPv4 ethertype appears 4 bytes later, after the VLAN header.

**Symptom:** stdout prints `33024` (decimal for `0x8100`) or mis-identifies protocol instead of `ip tcp ...`.

**Remediation:**

- Use **`-w capture.pcap`** and analyze with **tcpdump**, **Wireshark**, or tools that understand VLAN encapsulation.
- For custom parsing, implement **802.1Q decapsulation** (check for `ETHERTYPE_VLAN`, read VLAN ID, adjust offset before IP/TCP headers).
- pcap output uses `DLT_EN10MB`; Wireshark typically decodes VLAN if configured or if `vlan` keyword is used.

This is a **display limitation of the minimal stdout decoder**, not loss of tag data in the capture file.

---

## `ef_vi_capabilities_get()` and Sniff Capability Discovery

Applications sometimes call **`ef_vi_capabilities_get()`** to probe adapter features before allocation. For port sniff:

- The call may return **`ENOSYS`** on many driver/firmware combinations—meaning the capability API is **not implemented**, not that sniff is absent.
- Sniff availability is **not reliably reported** through this entry point in published etherfabric behavior.

**Recommended discovery approach:**

1. Attempt PD + VI allocation on the target interface.
2. Install RX port sniff filter; interpret errno (`EPERM`, `EOPNOTSUPP`, `EBUSY`).
3. If TX is needed, attempt `ef_filter_spec_set_tx_port_sniff()` separately.
4. Consult **`onload_tool license`**, firmware variant (ULL vs full), and **SolarCapture User Guide** for the adapter generation.

Do not gate production capture tooling solely on `ef_vi_capabilities_get()` sniff flags—they are often unavailable.

---

## Licensing: `RX_SNIFF` vs `TX_SNIFF`

Solarflare/AMD licenses encode feature flags consumed by firmware when MCDI sniff commands are issued.

| Product / license tier | Typical RX_SNIFF | Typical TX_SNIFF |
|------------------------|------------------|------------------|
| OpenOnload (base) | No | No |
| SolarCapture Plus | Sometimes partial / product-specific | Often no |
| **SolarCapture Pro** | **Yes** | **Yes** (full firmware) |
| Trial / evaluation keys | Time-limited both | Time-limited both |

Verify on the host:

```sh
onload_tool license
# Look for RX sniff / TX sniff / SolarCapture feature indicators
```

Without **RX_SNIFF**, enabling default port sniff in efvicap fails at `ef_vi_filter_add`. Without **TX_SNIFF**, `-o` fails even if RX capture works.

License installation is via **`sfboot`** / **`sfkey`** / vendor provisioning tools per **SolarCapture Installation Guide**—outside efvicap itself.

---

## Alternatives When TX Sniff Is Unavailable

When `-o` returns `EOPNOTSUPP` (ULL firmware, missing license, or unsupported hardware):

| Alternative | What it captures | Trade-offs |
|-------------|------------------|------------|
| **Switch SPAN / mirror port** | Egress (and ingress) on wire | Requires switch config; not host-local; timestamp/sync separate |
| **SolarCapture egress instance** | TX path via SolarCapture API with licensed sniff | Production-grade; needs SolarCapture Pro + compatible firmware |
| **Application-level logging** | Sent/received buffers in process | No wire-format pcap; misses firmware/offload details |
| **RX sniff only on peer port** | Traffic seen on opposite link direction | Incomplete for single-host bypass TX |
| **Full (non-ULL) firmware** | Enables `MC_CMD_SET_TX_PORT_SNIFF_CONFIG` | Latency profile changes; operational approval needed |

For Onload/TCPDirect egress visibility specifically, **TX port sniff** or **SPAN** remain the primary wire-accurate options.

---

## Operational Quick Reference

| Symptom | errno / message | Common cause | Action |
|---------|-----------------|--------------|--------|
| Cannot open driver | `EACCES`, `ENOENT` | Permissions / no sfc driver | Run with capability; load Onload driver |
| PD alloc fails on VLAN ifname | `ENODEV` | `ef_pd_alloc_by_name` needs physical port | Use physical NIC name + VLAN filter |
| RX sniff filter fails | `EPERM`, `EOPNOTSUPP` | No RX_SNIFF license | Install SolarCapture Pro license |
| TX sniff fails with `-o` | `EOPNOTSUPP` (95) | ULL firmware or no TX_SNIFF | Expect on ULL; use SPAN or full firmware |
| Second instance fails | `EBUSY` | Single sniff owner | Stop duplicate capture |
| Empty tcpdump on accelerated app | — | Kernel bypass | Use efvicap / RX port sniff |
| stdout shows `33024` | — | VLAN tag not parsed | Use pcap + Wireshark/tcpdump |
| Capability query useless | `ENOSYS` | API not implemented | Probe by installing sniff filter |

---

## Architecture (Conceptual)

```
     Wire / fabric
          |
          v
   +--------------+
   |  Solarflare  |
   |  MAC / NIC   |
   +--------------+
     |           |
     | RX mirror | TX mirror (if licensed + full FW)
     v           v
  ef_vi RX    ef_vi RX  (same or separate VI)
  queue       queue
     |           |
     v           v
  efvicap     efvicap
  (userspace) (userspace)
     |
     +-- stdout (minimal decode)
     +-- pcap file (-w)

  Parallel path: Onload/TCPDirect (kernel bypass) ----> does NOT appear in tcpdump
                                                      ----> DOES appear in port sniff mirror
```

---

## References

- **Onload Programmer's Guide** — ef_vi, PD/VI allocation, filters, port sniff
- **SolarCapture User Guide** — §4.4 firmware limitations (TX sniff on ULL), licensing, egress capture
- **SolarCapture API Reference** — `ef_filter_spec_set_port_sniff`, `ef_filter_spec_set_tx_port_sniff`
- **MCDI documentation** (adapter firmware) — `MC_CMD_SET_PORT_SNIFF_CONFIG`, `MC_CMD_SET_TX_PORT_SNIFF_CONFIG`
- **OpenOnload** — [http://www.openonload.org/](http://www.openonload.org/)

---

## efvicap Implementation Notes

For developers reading the source (`efvicap.cpp`):

- Default capture path uses **RX port sniff** when no positional filters are supplied.
- **`-o`** adds **TX port sniff** on the same VI after RX filters are installed.
- Positional filters replace the catch-all sniff with **multicast MAC** or **IPv4 UDP local** filters.
- Packet buffers use **huge pages** when available (`MAP_HUGETLB`), falling back to page-aligned allocations.
- **efct** RX path supports `EF_EVENT_TYPE_RX_REF` events via `efct_vi_rxpkt_get` / `efct_vi_rxpkt_release`.
- pcap writing uses a lock-free SPSC ring and a background writer thread; overflow increments a drop counter printed on exit.

These behaviors inherit the same platform limits documented above: naming, licensing, firmware SKU, and single-owner sniff semantics apply regardless of application.
