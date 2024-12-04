# Importing necessary modules from Scapy for creating IP and ICMP packets
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

def send_icmp_packet():
    """
    Creates and sends an ICMP packet with a TTL of 1.
    
    This function constructs an IP packet with a specified destination and a TTL
    (Time-to-Live) value of 1, which limits the packet to a single hop. The packet
    is then combined with an ICMP (Internet Control Message Protocol) layer to form
    an ICMP request packet. The packet is sent using the Scapy library's `send`
    function.

    Returns:
        None
    """
    IP_packet = IP(dst="receiver", ttl=1)  # Creating an IP packet with TTL=1
    ICMP_packet = ICMP()  # Creating an ICMP packet
    packet = IP_packet / ICMP_packet  # Combining IP and ICMP layers into one packet

    send(packet)  # Sending the packet to the specified destination
    print("ICMP packet sent with TTL=1")  # Confirmation message

if __name__ == "__main__":
    send_icmp_packet()  # Execute the sender function if run as the main script
