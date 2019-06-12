# DNSResolver

This program performs a lookup for a DNS server if its IPv4 address was not found previously (in cache). If one nameserver doesn't give a result, we try another equivalent nameserver. Lookups to a non-existent address (eg. blueberry.ubc.ca) queries the address to all name servers that handles ubc.ca.
