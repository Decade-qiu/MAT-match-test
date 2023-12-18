#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>

int main() {
    const char* pcapFile1 = "file1.pcap"; // 第一个文件路径
    const char* pcapFile2 = "file2.pcap"; // 第二个文件路径

    char errbuf[PCAP_ERRBUF_SIZE];

    // 打开第一个文件
    pcap_t* pcap1 = pcap_open_offline(pcapFile1, errbuf);
    if (pcap1 == nullptr) {
        std::cerr << "无法打开文件1：" << errbuf << std::endl;
        return 1;
    }

    // 打开第二个文件
    pcap_t* pcap2 = pcap_open_offline(pcapFile2, errbuf);
    if (pcap2 == nullptr) {
        std::cerr << "无法打开文件2：" << errbuf << std::endl;
        return 1;
    }

    // 逐个比较数据包
    struct pcap_pkthdr header1, header2;
    const u_char* packet1;
    const u_char* packet2;

    while ((packet1 = pcap_next(pcap1, &header1)) != nullptr && (packet2 = pcap_next(pcap2, &header2)) != nullptr) {
        // 假设是 IPv4 数据包
        const ip* ipHeader1 = reinterpret_cast<const ip*>(packet1 + 14); // 偏移 14 字节以跳过以太网头部
        const ip* ipHeader2 = reinterpret_cast<const ip*>(packet2 + 14);

        // 比较 IP 头部字段
        if (ipHeader1->ip_src.s_addr != ipHeader2->ip_src.s_addr ||
            ipHeader1->ip_dst.s_addr != ipHeader2->ip_dst.s_addr ||
            ipHeader1->ip_tos != ipHeader2->ip_tos ||
            ipHeader1->ip_id != ipHeader2->ip_id ||
            ipHeader1->ip_p != ipHeader2->ip_p ||
            ipHeader1->ip_srcport != ipHeader2->ip_srcport ||
            ipHeader1->ip_dstport != ipHeader2->ip_dstport) {
            std::cerr << "数据包字段不一致" << std::endl;
        }
    }

    // 关闭文件
    pcap_close(pcap1);
    pcap_close(pcap2);

    return 0;
}