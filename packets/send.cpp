#include <pcap.h>
#include <libnet.h>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <iomanip>

#define MAX_PACKET_SIZE 1500

// print pakcets info in hex
void printPacketData(const uint8_t* packet_data, size_t packet_size) {
    for (size_t i = 0; i < packet_size; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet_data[i]) << " ";
        if ((i + 1) % 16 == 0) {
            std::cout << std::endl;
        }
    }
    std::cout << std::dec << std::endl;
}

// build tcp header by packet_data
libnet_ptag_t build_tcp_header(libnet_t* libnet_handle, const uint8_t* packet_data) {
    const struct libnet_tcp_hdr* tcp_header = reinterpret_cast<const struct libnet_tcp_hdr*>(packet_data + sizeof(struct libnet_ipv4_hdr));
    uint16_t src_port = ntohs(tcp_header->th_sport);
    uint16_t dst_port = ntohs(tcp_header->th_dport);
    uint32_t src_ip = 0, dst_ip = 0;

    // 计算 TCP 伪首部的校验和
    uint32_t pseudo_sum = 0;
    pseudo_sum += (src_ip >> 16) & 0xFFFF;
    pseudo_sum += src_ip & 0xFFFF;
    pseudo_sum += (dst_ip >> 16) & 0xFFFF;
    pseudo_sum += dst_ip & 0xFFFF;
    pseudo_sum += htons(IPPROTO_TCP);
    pseudo_sum += htons(LIBNET_TCP_H);
    uint32_t tcp_data_len = 0; 
    uint32_t tcp_sum = 0;
    uint16_t* tcp_words = (uint16_t*)(tcp_header);
    for (int i = 0; i < LIBNET_TCP_H + tcp_data_len; i += 2) {
        if (i == LIBNET_TCP_H) {
            continue;
        }
        tcp_sum += ntohs(tcp_words[i / 2]);
    }
    uint32_t total_sum = pseudo_sum + tcp_sum;
    while (total_sum >> 16) {
        total_sum = (total_sum & 0xFFFF) + (total_sum >> 16);
    }

    return libnet_build_tcp(
        src_port,                // Source port
        dst_port,                // Destination port
        ntohl(tcp_header->th_seq), // Sequence number
        ntohl(tcp_header->th_ack), // Acknowledgment number
        tcp_header->th_flags,    // Control flags
        tcp_header->th_win,      // Window size
        0,                       // Checksum (0 means kernel will calculate it)
        0,                       // Urgent pointer
        LIBNET_TCP_H,            // TCP header length
        nullptr,                 // Payload (data)
        0,                       // Payload length
        libnet_handle,           // Libnet context
        0                        // Create a new TCP header
    );
}

// build udp header by packet_data
libnet_ptag_t build_udp_header(libnet_t* libnet_handle, const uint8_t* packet_data) {
    const struct libnet_udp_hdr* udp_header = reinterpret_cast<const struct libnet_udp_hdr*>(packet_data + sizeof(struct libnet_ipv4_hdr));
    uint16_t src_port = ntohs(udp_header->uh_sport);
    uint16_t dst_port = ntohs(udp_header->uh_dport);

    return libnet_build_udp(
        src_port,                // Source port
        dst_port,                // Destination port
        LIBNET_UDP_H + 0,        // UDP header length (including any payload data)
        0,                       // Checksum (0 means kernel will calculate it)
        nullptr,                 // Payload (data)
        0,                       // Payload length
        libnet_handle,           // Libnet context
        0                        // Create a new UDP header
    );
}

// build icmp header by packet_data
libnet_ptag_t build_icmp_header(libnet_t* libnet_handle, const uint8_t* packet_data) {
    const struct libnet_icmpv4_hdr* icmp_header = reinterpret_cast<const struct libnet_icmpv4_hdr*>(packet_data + sizeof(struct libnet_ipv4_hdr));

    return libnet_build_icmpv4_echo(
        icmp_header->icmp_type, // Type (e.g., ICMP_ECHO_REQUEST, ICMP_ECHO_REPLY)
        icmp_header->icmp_code, // Code
        0,                      // Checksum (0 means kernel will calculate it)
        ntohs(icmp_header->icmp_id), // ID
        ntohs(icmp_header->icmp_seq), // Sequence number
        nullptr,                // Payload (data)
        0,                      // Payload length
        libnet_handle,          // Libnet context
        0                       // Create a new ICMP header
    );
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " pcap_file interface_name" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle;
    pcap_handle = pcap_open_offline(argv[1], errbuf);

    if (pcap_handle == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    char * dev = argv[2];
    libnet_t* libnet_handle;
    char libnet_errbuf[LIBNET_ERRBUF_SIZE];
    libnet_handle = libnet_init(LIBNET_RAW4, dev, libnet_errbuf);

    if (libnet_handle == nullptr) {
        std::cerr << "Error initializing libnet: " << libnet_errbuf << std::endl;
        pcap_close(pcap_handle);
        return 1;
    }
        
    struct pcap_pkthdr packet_hdr;
    const u_char* packet_data;
    int num = 1;
    while ((packet_data = pcap_next(pcap_handle, &packet_hdr)) != nullptr) {
        if (packet_hdr.caplen > MAX_PACKET_SIZE) {
            std::cerr << "Packet size exceeds maximum allowed size." << std::endl;
            continue;
        }
        // Ensure the captured packet contains at least an IP header
        if (packet_hdr.caplen < sizeof(struct libnet_ipv4_hdr)) {
            std::cerr << "Invalid packet, IP header not found." << std::endl;
            continue;
        }
        // Extract IP header from the captured packet
        const struct libnet_ipv4_hdr* ip_header = reinterpret_cast<const struct libnet_ipv4_hdr*>(packet_data);

        // Prepare IP header fields
        uint8_t ip_version = 4; // IPv4
        uint8_t ip_tos = ip_header->ip_tos; // Type of Service (TOS)
        uint16_t ip_id = ntohs(ip_header->ip_id); // Identification
        uint16_t ip_frag = 0; // Fragmentation flags and offset (we don't use this in this example)
        uint8_t ip_ttl = ip_header->ip_ttl; // Time To Live (TTL)
        uint8_t ip_proto = ip_header->ip_p; // Protocol (e.g., IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP)
        uint16_t ip_checksum = 0; // Kernel will calculate the checksum

        uint32_t ip_src = ip_header->ip_src.s_addr; // Source IP address
        uint32_t ip_dst = ip_header->ip_dst.s_addr; // Destination IP address

        libnet_ptag_t transport_tag;
        if (ip_proto == IPPROTO_TCP) {
            transport_tag = build_tcp_header(libnet_handle, packet_data);
        } else if (ip_proto == IPPROTO_UDP) {
            transport_tag = build_udp_header(libnet_handle, packet_data);
        } else if (ip_proto == IPPROTO_ICMP) {
            transport_tag = build_icmp_header(libnet_handle, packet_data);
        }else{
            transport_tag = 0;
        }

        if (transport_tag == -1) {
            std::cerr << "Error building transport header: " << libnet_geterror(libnet_handle) << std::endl;
            pcap_close(pcap_handle);
            libnet_destroy(libnet_handle);
            return 1;
        }

        // Build the IP header
        uint32_t ip_packet_size = packet_hdr.caplen; // Total length of captured packet

        libnet_ptag_t ip_tag = libnet_build_ipv4(
            ip_packet_size,          // Total packet length, including header and data
            ip_tos,                  // Type of Service (TOS)
            ip_id,                   // Identification
            ip_frag,                 // Fragmentation flags and offset
            ip_ttl,                  // Time To Live (TTL)
            ip_proto,                // Protocol (e.g., IPPROTO_TCP, IPPROTO_UDP, IPPROTO_ICMP)
            ip_checksum,             // Kernel will calculate the checksum
            ip_src,                  // Source IP address
            ip_dst,                  // Destination IP address
            nullptr,                 // Pointer to the payload (data)
            0,                       // Payload length
            libnet_handle,           // Libnet context
            0                        // Create a new IP header
        );

        if (ip_tag == -1) {
            std::cerr << "Error building IP header: " << libnet_geterror(libnet_handle) << std::endl;
            pcap_close(pcap_handle);
            libnet_destroy(libnet_handle);
            return 1;
        }

        // Send the packet using libnet
        if (libnet_write(libnet_handle) == -1) {
            std::cerr << "Error sending packet: " << libnet_geterror(libnet_handle) << std::endl;
            pcap_close(pcap_handle);
            libnet_destroy(libnet_handle);
            return 1;
        }

        std::cout << "Packet " << num << " sent successfully! " << std::endl;
        num++;

        libnet_clear_packet(libnet_handle);
        // libnet_handle = libnet_init(LIBNET_RAW4, dev, libnet_errbuf);
    }

    pcap_close(pcap_handle);
    libnet_destroy(libnet_handle);
    return 0;
}
