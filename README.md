# Local network packet sniffer - spoofy

## Purpose
This package offers a command line utility able to intercept network trafic between two hosts on the local network, and to record the trafic caught applying to a given filter into a `.pcap` dump file.

It uses the arp poisoning (or arp spoofing) method to perform a Man In The Middle attack between the two targets and catch packets in the middle.

It is only able to work on IPv4 local networks.

## Compilation
Use `make` to compile the package. This should generate the `spoofy` executable.

## Usage
`$ spoofy [options] <target_1_ipv4> <target_2_ipv4> [filter_rule]`

#### Options
`-d` will detach the process from the shell and run it as a daemon.
<br>
This will log process output into a file named `sniffer.log`. You can change the name by editing the `DAEMON_LOG_FILE` macro in `includes/main.h` and re-compiling.

`-f <dump_file>` specify the name of the pcap formated file in which the captured packets are to be recorded.
<br>
Default is to create a new file `capture_n.pcap` where `n` is the next integer available.

`-s` Use a different MAC address while spoofing the two targets.
<br>
This option was not tested and might only work on wired network.
<br>
This could resolve the problem of having two IPv4 addresses having the same MAC address on the local network.

#### Targets

You have to specify the two targets IPv4 `<target_1_ipv4>` and `<target_2_ipv4>`. These addresses have to be on the same local network.
<br>
The program will automatically bind to a network interface on the good network and begin the spoofing.

#### Filter rule - optional
The filter rule is used to filter which intercepted packets have to be recorded into the `.pcap` dump file.
<br>
In addition to this filter the application will only record packet sent by one target for the other.

##### Rule syntax:

Rules can be combined into a logical rule using the following operators:<br>
`or`, `and`, `not`
<br>
In addition you can use parenthesis `(` and `)` to specify priority.

The following capture rules are available:
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

The default rule is `ip`

##### Rule examples:

1 - Capture DNS packets (udp and source or destination port is 53):
<br>`udp and port 53`
<br>Which is the same as:
<br>`udp and (port src 53 or port dst 53)`

2 - Capture ICMP packets from `10.0.0.1` or from `10.0.0.2`
<br>`icmp and (src 10.0.0.1 or src 10.0.0.2)`

3 - Capture ARP frames from/to `de:de:de:ab:ab:ab`
<br>`arp and ether de:de:de:ab:ab:ab`

### Results
The packets captured with this utility are stored in a `.pcap` file in the working directory.
<br>
This file can be opened with tools like Wireshark or Tcpdump to be analysed, or with the utility compiled in the `dissect/` repertory for a quick overview.

### Spoofing strategy
After sending ARP requests and receiving the corresponding replies from the targets, to get their MAC address, the program will try to define a poisoning strategy for each target.
<br>
It will try to poison a target with differents methods and test if the spoof worked usin ICMP ping request.

The different way of poisoning a target are:
<br>- Using a forged `arp announcement`
<br>- Using a forged `arp reply`
<br>- Using a forged `arp request`

This is done that way so the program can use `arp announcements` on targets instead of `arp replies`, if it works on them, because some devices can react poorly to gratuitous `arp reply` - ether ignore it or verify its integrity by flooding the network with `arp requests`.

If no answer is received from a target for our ICMP ping request, the default strategy is to poison the target with `arp replies`.

When the application is stopped (it received the SIGKILL or SIGTERM - crtl-c signals), it will send forged `arp replies` to reset the arp cache of the targets to normal.

### Target architectures
This package should compile on `MacOS` and `GNU/Linux`.
<br>It was tested on MacOS Sierra 10.12.5 and on the Linux kernel 5.3.7.
