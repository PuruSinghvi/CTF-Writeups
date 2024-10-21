## icmp 1
### Description
Once again, we've captured some network traffic. Once again, we believe the opposition have been pinging some important information across... can you try and find the flag?
### Files
[icmp2.pcapng](./icmp2.pcapng)

## Writeup
Opening this packet capture on Wireshark, we see a large amount of packets with several different protocols.
The description mentions "some important information", "pinging", so we know that we are interested in ICMP protocol's packets.
But since it mentions data is in it, we can try to search for it directly, considering we know the flag format `sun{}`.

So we use the expression: `frame contains "sun{"`
this leads us to two packets, number 5976 and 5977.
But both of these packets only contain the string `sun{` and nothing else.

To look at this with more context, we look for the packets around these two, and it turns out the flag was sent in pieces to multiple ICMP packets. Packet number 5976 to 5983 has all the parts of the flag, which we can join manually:
`sun{1cmp_1s_4un1337}`