# SonicWall SSL VPN reverse engineering experiments

This repo contains some scripts and code to MITM and reverse engineer the SonicWall SSL VPN protocol.
For a while, SonicWall was owned by Dell, so their name still appears in the context of their products from time to time.
In the future it might also contain prototype code that gets the cookie and eventually (that's the goal) establishes a connection.

## Official clients

There are two official clients from SonicWall.

* [SonicWall NetExtender](https://www.sonicwall.com/support/knowledge-base/how-can-i-download-and-install-netextender-on-linux/180105195559153/)
  (Linux, Windows, Mac)
* SonicWall Mobile Connect
  ([Android](),
   [Windows](https://www.sonicwall.com/support/knowledge-base/how-can-i-configure-ssl-vpn-connections-using-mobile-connect-on-windows-10/170502784131072/),
   [Mac](https://www.sonicwall.com/support/knowledge-base/how-can-i-configure-ssl-vpn-connections-using-mobile-connect-on-windows-10/170502784131072/))

The "SonicWall Global VPN client" (GVC) is for SonicWall's IPsec VPNs, i.e. it is not compatible with their "SSL VPN" which this repo is about.

## Demo instance

SonicWall provides a [demo instance](https://sslvpn.demo.sonicwall.com/) which is quite useful for development.

## Protocol

The protocol is relatively simple. After authenticating via HTTPS POST, a PPP-connection is tunneled via HTTPS.
The actual daemon only forwards packets between pppd an the TLS connection opened via HTTP CONNECT with the cookie retrieved from the authentication step.