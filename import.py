from pathlib import Path
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.utils import PcapNgReader
from typing import Optional


class PacketCapture:
    def __init__(self, filepath: Path, client_ip: str = '', server_ip: str = ''):
        self.filepath: Path = filepath
        self.packets: list[TCPPacket] = list()
        self.client_ip: str = client_ip
        self.server_ip: str = server_ip

    def decode_pcapng(self):
        if self.filepath.name[-6:] != "pcapng":
            raise ValueError(f'Provided file: {self.filepath} is not a .pcapng file.')

        pcap_reader = PcapNgReader(filename=str(self.filepath))
        self.packets = pcap_reader.read_all().res
        output_dict = dict()

        for i, packet in enumerate(self.packets):
            # Make sure we ignore other devices in the pcap by filtering out other IPs
            if (packet.ip_layer.src == self.client_ip or packet.ip_layer.src == self.server_ip) and \
                    (packet.ip_layer.dst == self.client_ip or packet.ip_layer.dst == self.server_ip):
                packet.direction = 'request' if packet.ip_layer.src == self.client_ip else 'response'

            # We can try to auto-detect the client/server by looking at who sent/received the SYN if IPs weren't given
            if not self.client_ip and str(packet.flags) == 'S':
                self.client_ip = packet.ip_layer.src
                self.server_ip = packet.ip_layer.dst

            # We're creating an entry in the dictionary that contains the request data as the key,
            # the "time_until_response" and "response" data as sub-values
            output_dict[i] = {
                "time_until_response": packet,
                "response": packet
            }
            # print(block._raw) #byte type raw data


class TCPPacket(Packet):
    """
    Extends scapy.packet.Packet
    """
    def __init__(self):
        super(TCPPacket, self).__init__()
        self.ip_layer = self.getlayer(IP)
        self.tcp_layer = self.getlayer(TCP)
        self.l2_layer = self.getlayer(Ether)

        self.direction: str = ''

    def decode_packet(self):
        pass


def import_folder(directory: Path):
    files = [f for f in directory.glob("**/*") if f.name[-6:] == "pcapng"]
    for filename in files:
        decoded_dict = decode_pcap(filename)
        #save_json(decoded_dict)


if __name__ == '__main__':
    import_folder(Path('captures/wireshark'))

