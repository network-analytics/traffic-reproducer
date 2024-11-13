#!/bin/bash

ip a

# Add more IPv4 addresses
for ip in ${ADDITIONAL_IPV4_LIST}; do
  ip addr add $ip dev eth0
done

# Add more IPv6 addresses
for ip in ${ADDITIONAL_IPV6_LIST}; do
  ip -6 addr add $ip dev eth0
done

ip a

# Execute the original entrypoint
exec "$@"