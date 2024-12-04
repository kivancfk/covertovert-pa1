# Importing necessary modules from Scapy for sniffing and filtering IP and ICMP packets
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff

def process_incoming_packet(packet):
    """
    Processes an incoming ICMP packet and displays it if specific conditions are met.

    The function checks if the incoming packet contains both IP and ICMP layers,
    and ensures that the TTL (Time-to-Live) value is 1 and ICMP type is 8 (ICMP request).
    If the conditions are met, the packet details are displayed using Scapy's `show` method.

    Args:
        packet (scapy.packet.Packet): The incoming packet captured by `sniff`.

    Returns:
        None
    """
    if IP in packet and ICMP in packet:
        # Checking for an ICMP request packet with TTL=1
        if packet[IP].ttl == 1 and packet[ICMP].type == 8:  
            print("Received ICMP request packet with TTL=1:")
            packet.show()  # Display packet details

def receive_icmp_packet():
    """
    Sniffs and processes ICMP packets using Scapy.

    This function initiates packet sniffing with a filter for ICMP packets and
    passes each captured packet to the `process_incoming_packet` function for further
    inspection and handling.

    Returns:
        None
    """
    sniff(filter="icmp", prn=process_incoming_packet)  # Sniff ICMP packets and process them

if __name__ == "__main__":
    receive_icmp_packet()  # Start sniffing for ICMP packets if run as the main script
