# Security Notes — Architecture Decisions

## SEC-5: Laptop-Hosted Manager (DMZ-to-Home Pivot Risk)

### The request
A user with a laptop and a rented VPS asked whether they could run LureGuard's Docker stack on their laptop and enrol the VPS as a Wazuh agent, keeping the SIEM on their home network.

### The instinct (half right)
**The security reflex is sound:** the monitoring plane should not be compromisable by the thing it monitors. If the SIEM runs on the box under attack, an attacker with root-level access can delete the evidence. Getting logs off the monitored host quickly and pushing them to a trusted location is textbook practice—real SIEMs do this.

### The implementation (a critical pivot)
**The naive architecture does not work**, and here's why:

Wazuh agents connect **outbound** to the manager. To reach a NAT'd laptop from a VPS, the user would port-forward `1514/1515` through their home router, exposing Wazuh's `authd` enrolment service to the internet.

This creates a **DMZ-to-trusted-zone pivot**: the VPS (an attacker-facing box, by premise) gains an authenticated network path into the home LAN. This is materially worse than the original problem—you swapped "logs deleted on the attacking host" for "attacker's authenticated access to the home network."

### If you take this approach anyway
1. **Never use router port-forwarding.** This makes the enrolment service internet-facing.
2. **Overlay network only.** Use Tailscale, WireGuard, or Nebula with strict ACLs:
   - VPS can reach only ports `1514` and `1515` on the manager.
   - Nothing else routes through the tunnel.
   - The overlay is encrypted and authenticated before any packet reaches the home network.
3. **Availability remains unsolved:** a laptop's uptime is not a monitoring system's uptime, and attacks happen at 3am. The SIEM being unavailable when attacked is its own failure mode.

### What we recommend
See [`docs/ARCHITECTURE-DECISIONS.md`](ARCHITECTURE-DECISIONS.md) ADR-4 (Shape A) for the production-grade topology: collector (Wazuh, Postgres, Core) on the VPS, analyst (opencode, MCP) on the laptop over an encrypted tunnel, no home-network exposure.
