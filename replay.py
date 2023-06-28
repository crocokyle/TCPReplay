import json
import logging
import socket
import sys
from pathlib import Path
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Packet

log = logging.getLogger('tcpreplay.replay')
stream_handler = logging.StreamHandler(sys.stdout)
log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
logging.basicConfig(format=log_format, level=logging.INFO, handlers=[
    logging.FileHandler("tcpreplay-replay.log"),
    stream_handler
])


def read_decoded_capture(filepath: Path) -> dict:
    log.info(f'Reading decoded capture from "{filepath}"')
    with open(filepath, 'r') as f:
        decoded_capture = json.load(f)

    return decoded_capture


def mock_server(capture: dict):
    host = '0.0.0.0' # Standard loopback interface address (localhost)
    port = int(capture['metadata']['server_port'])  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        log.info(f"listening on port {port}...")
        conn, addr = s.accept()
        with conn:
            log.info(f"Connection from {addr}")
            for expected_request, response in capture['mock_server'].items():
                request = conn.recv(len(expected_request['this_raw_packet']))
                log.info(f"Received request: {request.hex()}")
                if not request:
                    break
                conn.sendall(bytearray.fromhex(response.next_payload))
                log.info(f"Sent reply: {response.next_payload}")


if __name__ == '__main__':
    packet_capture = read_decoded_capture(Path('captures/decoded/350.json'))
    mock_server(packet_capture)
