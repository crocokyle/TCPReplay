import json
import logging
import sys
from pathlib import Path
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet
from scapy.utils import PcapNgReader

log = logging.getLogger('TCPReplay.import')
stream_handler = logging.StreamHandler(sys.stdout)
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(format=log_format, level=logging.INFO, handlers=[
    logging.FileHandler(f"tcp_relay.log"),
    stream_handler
])


class TCPPacket:
    """
    Adds some attributes to scapy.packet.Packet
    Not using inheritance because the Packet object has no repr
    """

    def __init__(self, scapy_packet):
        self.scapy_packet: Packet = scapy_packet
        self.ip_layer = scapy_packet.getlayer(IP)
        self.tcp_layer = scapy_packet.getlayer(TCP)
        self.l2_layer = scapy_packet.getlayer(Ether)

        self.direction: str = ''
        self.sequence_id: int = self.tcp_layer.seq


class PacketCapture:
    def __init__(self, filepath: Path, client_ip=None, server_ip=None, client_port=None, server_port=None):
        if filepath.name[-6:] != "pcapng":
            raise ValueError(f'Provided file: {filepath} is not a .pcapng file.')
        self.filepath: Path = filepath
        # Eventually might want to add support for other pcap types here
        self.packets: list[TCPPacket] = [TCPPacket(p) for p in PcapNgReader(filename=str(self.filepath)).read_all().res]

        if not server_ip or not client_ip:
            (self.client_ip, self.client_port), (self.server_ip, self.server_port) = self._autodetect_client_server()
        else:
            self.client_ip: str = client_ip
            self.server_ip: str = server_ip
            self.client_port: int = client_port
            self.server_port: int = server_port

        self.filtered = False

    def _autodetect_client_server(self) -> tuple[tuple[str, int], tuple[str, int]]:
        """
        We can try to auto-detect the client/server by looking at who sent/received the SYN if IPs weren't given
        """
        for packet in self.packets:
            if str(packet.tcp_layer.flags) == 'S':
                client_ip = packet.ip_layer.src
                server_ip = packet.ip_layer.dst
                client_port = packet.tcp_layer.sport
                server_port = packet.tcp_layer.dport

                return (client_ip, client_port), (server_ip, server_port)

        raise ValueError(f'No SYN packet found in packet capture')

    def _get_next_packet(self, index: int, direction: str) -> Optional[TCPPacket]:
        """
        Find the next response packet from an index in the packet capture list
        """
        this_packet = None
        if index < len(self.packets):
            this_packet = self.packets[index]
            for packet in self.packets[index:]:
                if packet.direction != direction:
                    return packet

        replier_ip = self.client_ip if direction == 'response' else self.server_ip
        if this_packet:
            log.warning(
                f'No {direction}s from {replier_ip} found after: "{this_packet.tcp_layer.payload.original.hex()}"'
            )
        return None

    def assign_packet_direction(self) -> None:
        if not self.filtered:
            self.filter_outsiders()
        for packet in self.packets:
            if packet.tcp_layer.dport == self.server_port:
                packet.direction = 'request'
            elif packet.tcp_layer.dport == self.client_port:
                packet.direction = 'response'
            else:
                log.warning(f'Found unfiltered packet in capture: {packet}')
                continue

    def filter_outsiders(self) -> list[TCPPacket]:
        """
        Filter out IPs that aren't the between client or server
        """
        if not self.client_ip or not self.server_ip:
            raise ValueError(f'Missing client or server IP')

        filtered_packets = list()
        for packet in self.packets:
            if not packet.tcp_layer.payload:
                continue
            if ((packet.ip_layer.src == self.client_ip and packet.ip_layer.dst == self.server_ip) and (
                    packet.tcp_layer.sport == self.client_port and packet.tcp_layer.dport == self.server_port)) or (
                    (packet.ip_layer.src == self.server_ip and packet.ip_layer.dst == self.client_ip) and (
                    packet.tcp_layer.sport == self.server_port and packet.tcp_layer.dport == self.client_port)):
                filtered_packets.append(packet)

        self.packets = filtered_packets
        self.filtered = True
        return self.packets

    def generate_output(self) -> dict:
        """
        Generates two dictionaries: one where packets are keyed for mocking a server and one for mocking a client.
        The keys in each contain the packet that the mock device expects to receive and what it should send back.
        """
        mock_server_output = dict()
        mock_client_output = dict()
        if not self.filtered:
            self.filter_outsiders()
        self.assign_packet_direction()
        for i, packet in enumerate(self.packets):
            next_packet: Optional[TCPPacket] = self._get_next_packet(i, packet.direction)
            time_until_next: float = 0 if not next_packet else next_packet.tcp_layer.time - packet.tcp_layer.time
            next_payload: Optional[str] = None if not next_packet else next_packet.tcp_layer.payload.original.hex()
            next_raw_packet: Optional[str] = None if not next_packet else next_packet.scapy_packet.original.hex()

            dict_to_update = mock_server_output if packet.direction == 'request' else mock_client_output
            dict_to_update[f"{packet.sequence_id}.{packet.tcp_layer.payload.original.hex()}"] = {
                "time_until_next": time_until_next,
                "next_payload": next_payload,
                "this_raw_packet": packet.scapy_packet.original.hex(),
                "next_raw_packet": next_raw_packet,
            }

        output = {
            "mock_server": mock_server_output,
            "mock_client": mock_server_output,
        }

        return output

    @staticmethod
    def export_json(filename: str, output: dict):
        directory = Path('captures/decoded')
        directory.mkdir(parents=True, exist_ok=True)
        with open(Path(directory, filename), 'w') as fp:
            json.dump(output, fp, indent=4)


def import_folder(directory: Path):
    log.info(f'Searching for pcapng files in "{directory}"...')
    file_paths = [f for f in directory.glob("**/*") if f.name[-6:] == "pcapng"]
    log.info(f'Parsing {len(file_paths)} pcapng file(s)...')
    for path in file_paths:
        log.info(f'Parsing {path.name}...')
        packet_capture = PacketCapture(path)
        output_data: dict = packet_capture.generate_output()
        export_filename = f"{path.name.split('.')[0]}.json"
        log.info(f'Exporting packet capture to "{export_filename}"...')
        packet_capture.export_json(export_filename, output_data)
    log.info(f'Finished importing packet captures from "{directory}"')


if __name__ == '__main__':
    import_folder(Path('captures/wireshark'))
