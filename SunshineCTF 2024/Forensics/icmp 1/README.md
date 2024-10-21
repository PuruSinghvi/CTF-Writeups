## icmp 1
### Description
We've captured some network traffic, our intelligence team believes the opposition have pinged some important data across, can you find it?
### Files
[icmp1.pcapng](./icmp1.pcapng)

## Writeup
Opening this packet capture on Wireshark, we see a large amount of packets with several different protocols.
The description mentions "some important data" was "pinged", so we know that we are interested in ICMP protocol's packets.
But since it mentions data is in it, we can try to search for it directly, considering we know the flag format `sun{}`.

So the expression: `frame contains "sun{"`
leads us to packet number 3135, which has the flag!
```
Hello, it's nice to finally reach you. Here is the sensitive information you've been requesting: sun{0n1y_a_p1ng_@way}
```