#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <iomanip>

int num;
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

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet_data) {
    struct libnet_ipv4_hdr *iph;
    struct tcphdr *tcph;
    // printPacketData(packet_data, 50);
    iph = (struct libnet_ipv4_hdr *)(packet_data+14); // 偏移14字节以跳过以太网头部
    if (iph->ip_tos != 0xff) return;
    num++;
    std::cout << num << " packet" << "  id " << ntohs(iph->ip_id) << std::endl;
    // 打印源IP、目标IP和目标端口
    // std::cout << inet_ntoa(iph->ip_src) << " " << inet_ntoa(iph->ip_dst) << std::endl;
}

int main() {
    num = 0;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr header;
    const u_char *packet;

    char * dev = "veth1_MAT";

    // 打开网络设备
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // 替换为实际的网络设备名称

    // 抓包并调用packet_handler处理每个包
    pcap_loop(handle, 0, packet_handler, NULL);

    // 关闭网络设备
    pcap_close(handle);

    return 0;
}
