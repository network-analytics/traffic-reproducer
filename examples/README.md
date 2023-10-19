# Traffic Reproducer Examples

sudo env PATH="$PATH" python main.py -v -t examples/ipfix-traffic.yml --no-sync
sudo env PATH="$PATH" python main.py -v -t examples/ipfix-traffic.yml

sudo env PATH="$PATH" python main.py -v -t examples/bgp-traffic.yml
sudo env PATH="$PATH" python main.py -v -t examples/bmp-traffic.yml

