# Packet dissection & display utility

### Purpose

This package offers a little console utility to parse and display `.pcap` files content. Its primary purpose is to display a fast summary of packets captured with `spoofy`.

Note that software like Wireshark or Tcpdump are more suitable to open `.pcap` files as this utility is very basic and only handle main internet protocols.

#### Compilation
Use `make` to compile. This will produce the executable `dct`.

#### Usage
`$ dct <file.pcap>`

#### Navigation

You can navigate in the packets list & packet summary using the following keys :

In the packets list
* arrow keys (up/down) -> previous/next packet
* space -> page down
* crtl-b -> page up
* slash (/) -> enter a command
* enter -> display selected packet summary / validate command
* erase -> erase a character in the command
* crtl-q -> quit application

In the packet summary view
* arrows key (up/down) -> scroll up/down
* arrows key (left/right) -> previous/next packet
* space -> page down
* ctrl-b -> page up
* escape -> go back to packets list
* crtl-q -> quit application

#### Commands

##### filter packets
`/filter <filter_rule>`
<br>
The filter rule syntax is the same as spoofy. Refer to the spoofy README.md. This will only display packets applying to the given filter.

##### remove filter
`/no filter`
<br>
This will remove previously applied filter
