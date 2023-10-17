#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries

# Ancora da pensare bene (perché i timestamps vengono anche aggiustati da i singoli process_protocol --> perché è necessario tipo lasciare 1s tra BGP OPEN e UPDATES being sent...etc...)
#  --> quindi questa funzione deve fare il merge aggiustando i timestamps ma mantenendo invariati gli inter-packet delays! --> modifica solo inter protocol delays...
def merge_and_adjust_timestamps(packets_list):
    return
