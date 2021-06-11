# Local network packet sniffer

## Purpose
Command line utility able to intercept specific network traffic between two hosts on a local network, and records the caught packets into a `.pcap` dump file.

Uses arp spoofing to catch packets between the two targets.

Only works on IPv4 local networks.

## Compilation
Compile with `make`. This will generate the `spoofy` executable.

## Usage
`$ spoofy [options] <target_1_ipv4> <target_2_ipv4> [filter_rule]`

#### Options
`-d` run as daemon.
<br>
Logs process output into a file named `sniffer.log`. You can change the name by editing the `DAEMON_LOG_FILE` macro in `includes/main.h` and re-compiling.

`-f <dump_file>` name of the pcap formatted where the capture will be saved.
<br>
Default is `capture_n.pcap`.

`-s` use a different MAC address while spoofing the two targets (avoid having two ip addresses linked to the same MAC address)

#### Targets

Two targets defined by their ip addresses `<target_1_ipv4>` and `<target_2_ipv4>`. These addresses have to be on the same local network.

#### Filter rule - optional
The filter rule is used to filter which intercepted packets have to be recorded into the `.pcap` dump file.

##### Rule syntax:

Rules are constructed using the following logical operators:<br>
`or`, `and`, `not`
<br>
You can use parenthesis `(` and `)` to specify priority.

Available capture filters:
<br>`ip` - Only capture IPv4 packets
<br>`arp` - Only capture ARP frames
<br>`icmp` - Only capture ICMP packets, implies `ip`
<br>`udp` - Only capture UDP datagrams, implies `ip`
<br>`tcp` - Only capture TCP segments, implies `ip`
<br>`ether src <MAC_address>` - Only capture frames coming from given ethernet source
<br>`ether dst <MAC_address>` - Only capture frames intended for given ethernet destination
<br>`ether <MAC_address>` - Only capture frames intended for or sent by given ethernet address
<br>`src <IPv4_address>` - Only capture packets coming from given source, implies `ip`
<br>`dst <IPv4_address>` - Only capture packets intended for given destination, implies `ip`
<br>`host <IPv4_address>` - Only capture packets intended for or sent by given ip address, implies `ip`
<br>`port src <port_number>` - Only capture packets coming from given port source, implies `ip and (tcp or udp)`
<br>`port dst <port_number>` - Only capture packets intended for given port destination, implies `ip and (tcp or udp)`
<br>`port <port_number>` - Only capture packets intended for or sent by given port, implies `ip and (tcp or udp)`

Default rule is `ip`

##### Rule examples:

1 - Capture DNS packets (udp and source or destination port 53):
<br>`udp and port 53`
<br>Which is the same as:
<br>`udp and (port src 53 or port dst 53)`

2 - Capture ICMP packets coming from `10.0.0.1` or from `10.0.0.2`
<br>`icmp and (src 10.0.0.1 or src 10.0.0.2)`

3 - Capture ARP frames from/to `de:de:de:ab:ab:ab`
<br>`arp and ether de:de:de:ab:ab:ab`

### Results
Captured packets are stored into a `.pcap` file.
<br>
This file can be opened with tools like Wireshark or Tcpdump to be analysed, or with the utility compiled in the `dissect/` repertory for a quick overview.

### Spoofing strategy
First sends ARP requests to get targets MAC addresses.
<br>
Then try to poison a target with different methods, test the efficiency of a method using ICMP ping requests.

The different way of poisoning are:
<br>- Using a forged `arp announcement`
<br>- Using a forged `arp reply`
<br>- Using a forged `arp request`

It prefers `arp announcements` poisoning over `arp replies` - some devices can react poorly to gratuitous `arp reply`.

If no answer is received from a target for the ICMP ping request, the default strategy is to poison the target with `arp replies`.

When the application is stopped (it received the SIGKILL or SIGTERM - crtl-c signals), it will send forged `arp replies` to reset the arp cache of the targets to normal.

### Target architectures
Should work on Unix systems, was tested on MacOS Sierra 10.12.5 and on Linux kernel 5.3.7.
