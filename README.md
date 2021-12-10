QUIC-LB
===

QUIC-LB is a set of common algorithms that allow a QUIC server to incorporate
a "Server ID" in its Connection ID, and for a low-state load balancer to
extract that connection ID for routing purposes.

The QUIC Working Group [Editor's draft] 
(https://quicwg.org/load-balancers/draft-ietf-quic-load-balancers.html)
specifies the design.

Building QUIC-LB
---

1. Clone this project from git.
2. Install openssl
3. % make

Guide to files
---
This project provides a library for load balancer and QUIC server
implementations to generate and decode compliant connection IDs, given a
consistent configuration.

This library is contained in quic_lb.h and quic_lb.c. As this code was
originally developed for a proprietary microkernel environment, quic_lb_types.h
is also required to compile in conventional Linux.

quic_lb_test.c creates a series of valid configurations, generates connection
IDs for those configurations, and then extracts the server ID to check that it
is recoverable. The Makefile compiles this test code, generating a full report
of configuration parameters.

Contribution Guidelines
---

Contributions are welcome. However, F5 corporate policy requires contributors to
complete the Contributor License Agreement and email it to a.macedonia@f5.com.
The CLA is in the root directory of this repo.
