DNSSeeder
====

[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](https://choosealicense.com/licenses/isc/)

DNSSeeder exposes a list of known peers to any new peer joining the Kaspa network via the DNS protocol.

When DNSSeeder is started for the first time, it will connect to the kaspad node
specified with the `-s` flag and listen for `addr` messages. These messages
contain the IPs of all peers known by the node. DNSSeeder will then connect to
each of these peers, listen for their `addr` messages, and continue to traverse
the network in this fashion. DNSSeeder maintains a list of all known peers and
periodically checks that they are online and available. The list is stored on
disk in a json file, so on subsequent start ups the kaspad node specified with
`-s` does not need to be online.

When DNSSeeder is queried for node information, it responds with details of a
random selection of the reliable nodes it knows about.

It is written in Rust.

This project is currently under active development and is in Beta state.


## Requirements

Latest Rust toolchain and `protoc` (Protocol Buffers compiler).

## Getting Started

- Install Rust via rustup: https://rustup.rs/

- Ensure Rust was installed properly:

- Launch a kaspad node for the DNSSeeder to connect to

```bash
$ rustc --version
$ cargo --version
```

- Run the following commands to obtain and build dnsseeder:

```bash
$ git clone https://github.com/elldeeone/rusty-dnsseeder.git
$ cd rusty-dnsseeder
$ cargo build --release
```

- The dnsseeder binary will be at `./target/release/dnsseeder`.

To start dnsseeder listening on udp 127.0.0.1:5354 with an initial connection to a working testnet node running on 127.0.0.1:

```
$ ./target/release/dnsseeder -n nameserver.example.com -H network-seed.example.com -s 127.0.0.1 --testnet
```

You will then need to redirect DNS traffic on your public IP port 53 to 127.0.0.1:5354
Note: to listen directly on port 53 on most Unix systems, one has to run dnsseeder as root, which is discouraged

## Setting up DNS Records

To create a working set-up where the DNSSeeder can provide IPs to kaspad instances, set the following DNS records:
```
NAME                        TYPE        VALUE
----                        ----        -----
[your.domain.name]          A           [your ip address]
[ns-your.domain.name]       NS          [your.domain.name]
```
