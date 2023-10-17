#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

def get_layers(packet, do_print=False):
    layers = []
    counter = 0

    print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
    while True:
        layer = packet.getlayer(counter)
        if layer is None: break
        layers.append(layer)
        
        if do_print:
            print(layer)
        counter += 1
        
    if do_print: print("Number of layers: ", counter)

    return layers