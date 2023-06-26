from pathlib import Path
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.utils import PcapNgReader
from typing import Optional


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
        # TODO: This method might not be needed
        pass


class PacketCapture:
    def __init__(self, filepath: Path, client_ip=None, server_ip=None):
        if filepath.name[-6:] != "pcapng":
            raise ValueError(f'Provided file: {filepath} is not a .pcapng file.')
        self.filepath: Path = filepath

        # TODO: maybe add support for other types of pcap
        self.packets: list[TCPPacket] = PcapNgReader(filename=str(self.filepath)).read_all().res
        self.client_ip: str = client_ip or self._autodetect_client_server()[0]
        self.server_ip: str = server_ip or self._autodetect_client_server()[1]

    def _autodetect_client_server(self) -> tuple[str, str]:
        """
        We can try to auto-detect the client/server by looking at who sent/received the SYN if IPs weren't given
        """
        for packet in self.packets:
            if not self.client_ip and str(packet.flags) == 'S':
                client_ip = packet.ip_layer.src
                server_ip = packet.ip_layer.dst

                return client_ip, server_ip

        raise ValueError(f'No SYN packet found in packet capture')

    def filter_outsiders(self) -> list[TCPPacket]:
        """
        Filter out IPs that aren't the between client or server
        """
        if not self.client_ip or not self.server_ip:
            raise ValueError(f'Missing client or server IP')

        filtered_packets = list()
        for packet in self.packets:
            if (packet.ip_layer.src == self.client_ip or packet.ip_layer.src == self.server_ip) and \
                    (packet.ip_layer.dst == self.client_ip or packet.ip_layer.dst == self.server_ip):
                filtered_packets.append(packet)

        self.packets = filtered_packets
        return self.packets

    def generate_output(self) -> dict:
        output_data = dict()
        self.filter_outsiders()
        for i, packet in enumerate(self.packets):
            packet.direction = 'request' if packet.ip_layer.src == self.client_ip else 'response'

            # We're creating an entry in the dictionary that contains the request data as the key,
            # the "time_until_response" and "response" data as sub-values
            output_data[] = {
                "time_until_response": packet,
                "response": packet
            }
            # print(block._raw) #byte type raw data

        return output_data

    @staticmethod
    def export_json(output_data):
        pass


def import_folder(directory: Path):
    files = [f for f in directory.glob("**/*") if f.name[-6:] == "pcapng"]
    for filename in files:
        packet_capture = PacketCapture(filename)
        output_data = packet_capture.generate_output()
        packet_capture.export_json(output_data)


if __name__ == '__main__':
    import_folder(Path('captures/wireshark'))

