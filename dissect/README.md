# Packet dissection utility

### Purpose

Command line utility to parse and display `.pcap` file content. Can be used to get fast summary of captured packets.

Software like Wireshark or Tcpdump are more suitable to open `.pcap` captures as they will provide more information, and handle more protocols.

#### Compilation
Compile with `make`. This will produce the executable `dct`.

#### Usage
`$ dct <file.pcap>`

#### Navigation

Navigation into the packets list & packet summary.

In the packets list
* arrow keys (up/down) -> previous/next packet
* space -> page down
* crtl-b -> page up
* slash (/) -> enter a command
* enter -> display selected packet summary / validate command
* crtl-q -> quit application

In the packet summary view
* arrows key (up/down) -> scroll up/down
* arrows key (left/right) -> previous/next packet
* space -> page down
* ctrl-b -> page up
* escape -> go back to packets list
* crtl-q -> quit application

#### Available commands

##### filter packets
`/filter <filter_rule>`
<br>
Only show packets applying to given filter. Same filter rule as in the spoofy utility.

##### remove filter
`/no filter`
<br>
Remove previously applied filter
