# Router setup, IPv6 and DNS bypasses

The blocker only sees queries that are sent to it. This page covers how to make
every device on your network use it, why **IPv6 can silently bypass it**, and how to
check the result. The same ideas apply to any router.

> Router menus differ between models and firmware versions (ISPs often supply routers
> from several makers). The names below are the usual ones; look for the closest
> match on your router's admin page (often `http://192.168.1.1`).

## 1. Give the blocker a fixed address

The device's IP must not change, or clients will lose DNS.

- In the router: **LAN → DHCP → Static lease / Address reservation**, reserve an IP
  for the device's MAC (shown on the serial log and the dashboard).

## 2. Hand the blocker out as DNS (IPv4)

Best: tell the router's DHCP server to give clients the blocker as their DNS server.

- **LAN → DHCP server → Primary DNS** = the blocker's IP. Leave secondary DNS
  **empty** (a public secondary such as 8.8.8.8 lets clients skip the blocker
  whenever they like).
- Some ISP routers lock these fields. On some fibre (GPON) gateways the customer
  login shows LAN DNS, the DHCP on/off switch, static DHCP leases, IPv6 LAN DNS and
  the WAN settings all greyed out, so §1–§3 can't be done there. Options if yours
  does:
  - **Put your own router behind it** (works even on a fully locked box): see
    [§2a](#2a-your-own-router-behind-a-locked-isp-router).
  1. Set DNS per device (Wi-Fi settings → IP/DNS → manual) on the devices you care
     about.
  2. Turn off the router's DHCP server and run DHCP elsewhere (another router in
     access-point mode, or a small server). _(The device does not run a DHCP server
     yet; see the roadmap.)_
  3. Point only the router's **WAN/Internet DNS** at the blocker. Clients then still
     ask the router, which forwards to the blocker. This works, but every query
     appears to come from the router, so per-client stats and bans show one client.

### 2a. Your own router behind a locked ISP router

Leave the ISP router as it is and plug a second router's **WAN/Internet** port into
one of its LAN ports. The second router runs its own network, which you fully control:

1. Second router: **Router** mode (not access point), internet type **Dynamic IP**.
2. Join the blocker to the second router's Wi-Fi (dashboard _Forget Wi-Fi_, or hold
   BOOT while powering on, then pick the new network on its setup page).
3. Reserve the blocker's IP (by its MAC) in the second router's DHCP settings.
4. Make that router hand out the blocker as DNS, with no secondary DNS.
5. Turn off IPv6 on the second router.
6. Move your devices to the second router's Wi-Fi; plug wired devices into it too.
   Anything left on the ISP router's Wi-Fi or ports still uses the ISP's DNS.

Example, a typical TP-Link home router behind a locked ISP gateway: its DHCP page
has no DNS fields, but it passes its own internet DNS to clients, so step 4 is
_Network → Internet → Advanced → Use the Following DNS Addresses_ = the blocker's IP.
Address reservation is under _Network → LAN Settings_, and IPv6 is the _IPv6 Enable_
switch on the Internet page. `s3adblock.local` only resolves on the network the
blocker is on; from elsewhere use its IP. Mesh systems work the same way if they let
you set the DNS their DHCP hands out (TP-Link Deco: _More → Advanced → DHCP Server →
Primary DNS_).

## 3. IPv6: the most common bypass

Many fibre and cable connections are dual-stack. The router announces **its own (or
the ISP's) IPv6 DNS servers** to clients through router advertisements (RDNSS) and
DHCPv6. Phones and laptops happily use those for some or all lookups, so ads load
even though IPv4 DNS points at the blocker.

The blocker answers DNS over IPv4 only (it blocks AAAA lookups that reach it, but it
cannot stop clients from asking a different IPv6 server). Pick one of these:

| Option                                                    | How                                                                                                            | Trade-off                                                         |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| **A. Stop advertising IPv6 DNS** (preferred if available) | In the router's IPv6/LAN settings, disable "DNS server" / "RDNSS" / "DHCPv6 DNS", or set the IPv6 DNS to none. | Keeps IPv6 connectivity; not every router offers it.              |
| **B. Disable IPv6 on the LAN**                            | **IPv6 → LAN** (or **Network → IPv6**) → disable, or set the WAN connection to IPv4 only.                      | Simple and reliable; loses IPv6 (most sites work fine over IPv4). |
| **C. Per device**                                         | Turn off IPv6 on the device, or set its IPv6 DNS manually to nothing / a blocked address.                      | Only covers the devices you change.                               |

ISP-managed routers sometimes get settings re-applied remotely or after a firmware
update or reset: re-check after any router change.

## 4. Browser and OS "secure DNS"

Encrypted DNS built into browsers and phones talks to a public resolver directly,
skipping your network's DNS.

- **Firefox:** the blocker answers Firefox's canary domain
  (`use-application-dns.net`) with NXDOMAIN, which tells Firefox not to enable its
  automatic DoH. If a user turned DoH on manually (Settings → Privacy → DNS over
  HTTPS → "Max protection"), Firefox bypasses the blocker by design.
- **Chrome / Edge:** "Use secure DNS" set to "With your current service provider"
  only upgrades when the system resolver is a known DoH provider (the blocker is
  not), so it keeps using the blocker. A custom provider chosen there bypasses it.
- **Android:** Settings → Network → **Private DNS** must be **Off** or **Automatic**.
  A hostname there (e.g. `dns.google`) bypasses the blocker.
- **Apple devices:** iCloud Private Relay bypasses local DNS for Safari. The
  dashboard option _Disable iCloud Private Relay on this network_ answers Apple's
  opt-out domains so devices fall back to normal DNS (off by default).

## 5. Devices with hard-coded DNS

Some smart TVs, streaming sticks and apps ignore DHCP and use fixed resolvers such as
8.8.8.8, or DNS-over-HTTPS. Only a router firewall rule can stop that (block or
redirect outbound port 53/853 except from the blocker). Many ISP routers don't
support such rules.

## 6. Check that it works

From a client on the network:

```bash
# Which DNS servers is this machine using?
scutil --dns | grep nameserver          # macOS
ipconfig /all                           # Windows (look for "DNS Servers", IPv4 and IPv6)
resolvectl status                       # Linux (systemd-resolved)

# Blocked names come back as 0.0.0.0 / :: from the blocker
nslookup doubleclick.net                # should show the blocker's IP as Server, 0.0.0.0 as Address
dig doubleclick.net AAAA                # ::  (with the blocker as server)
dig @<blocker-ip> example.com +short    # a real answer

# Is anything reaching another resolver over IPv6?
dig -6 doubleclick.net                  # if this returns a real ad-server address, IPv6 DNS bypasses the blocker
```

The dashboard's client table also helps: a device that never appears there (or
shows almost no queries) is using some other DNS server.
