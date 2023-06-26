from pathlib import Path
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.utils import PcapNgReader
from typing import Optional


class TCPPacket:
    def __init__(self, packet):
        self.packet = packet
        self.ip_layer = packet.getlayer(IP)
        self.tcp_layer = packet.getlayer(TCP)
        self.l2_layer = packet.getlayer(Ether)


def import_folder(directory: Path):
    files = [f for f in directory.glob("**/*") if f.name[-6:] == "pcapng"]
    for filename in files:
        decoded_dict = decode_pcap(filename)
        #save_json(decoded_dict)


def decode_pcap(filename) -> dict:
    pcap_reader = PcapNgReader(filename=str(filename))
    packets = pcap_reader.read_all().res
    output_dict = dict()
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None

    for i, packet in enumerate(packets):
        # We determine who is a client/server by looking at who sent/received the SYN...this is probably bad
        if str(tcp_pkt.flags) == 'S':
            client_ip = ip_pkt.getlayer(IP).src
            server_ip = ip_pkt.getlayer(IP).dst

        if client_ip and server_ip:
            # Make sure we ignore other devices in the pcap
            if (ip_pkt.src == client_ip or ip_pkt.src == server_ip) and \
                    (ip_pkt.dst == client_ip or ip_pkt.dst == server_ip):

                p_type = 'request' if ip_pkt.src == client_ip else 'response'

                # We're creating an entry in the dictionary that contains the request data as the key,
                # the "time_until_response" and "response" data as subvalues
                output_dict[i] = {
                    "time_until_response": packet,
                    "response": packet
                }
                # print(block._raw) #byte type raw data


if __name__ == '__main__':
    import_folder(Path('captures/wireshark'))

