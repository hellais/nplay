# Nplay

An attempt at sonifying network traffic.

It works by either sniffing on the network interface or replaying a pcap file
and encoding some features as
[OSC](https://en.wikipedia.org/wiki/Open_Sound_Control) messages. These are
then received by a [Max patch](https://en.wikipedia.org/wiki/Max_(software))
and used to create generative sounds.

Usage:

1. Open the Max patch `nplay.maxpat`

2. Start `nplay.py` with `python nplay.py` (you should have first installed `requirements.txt`

3. Listen

You can use `nplay.py` either on your network card with `nplay.py --interface
en0` or from a pcap file: `nplay.py --pcap traffic.pcap`.

It's best that you also specificy your IP address with `--my-ip` so that it can
generate different features if the network traffic is inbound or outbound.

You can also pass a `--time-warp` parameter so say if the traffic should be slowed down or sped up (ex. `--time-warp 2` means 2x slower).

