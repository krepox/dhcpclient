# DHCP Client

<p align="justify">
DHCP client implemented in Go that provides an user with connectivity to a DHCP Server. It attaches to a network interface and stays waiting until Server activates the client. At activating, erases current IP address in the attached network, and then starts the DORA (Discover, Offer, Request, ACK) process with the server. It also supports the DHCP ForceRenewNonCapable primitive
</p>
