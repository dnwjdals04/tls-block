#include <iostream>
#include <pcap.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <string>
#include <vector>
#include <map>
#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"


void usage() {
    std::cout << "syntax : tls-block <interface> <server name>\n";
    std::cout << "sample : tls-block wlan0 naver.com\n";
}

Mac local_mac;

struct Key {
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    bool operator<(const Key& other) const {
        return std::tie(sip, dip, sport, dport) < std::tie(other.sip, other.dip, other.sport, other.dport);
    }
};
std::string extract_sni(const uint8_t* data, int len) {
    int pos = 0;
    pos += 5;  // TLS Record Header
    pos += 4;  // Handshake Header
    if (pos + 34 > len) return ""; // Version(2) + Random(32)
    pos += 34;

    // Session ID
    if (pos + 1 > len) return "";
    int session_id_len = data[pos];
    pos += 1 + session_id_len;

    // Cipher Suites
    if (pos + 2 > len) return "";
    int cipher_len = (data[pos] << 8) | data[pos + 1];
    pos += 2 + cipher_len;

    // Compression Methods
    if (pos + 1 > len) return "";
    int comp_len = data[pos];
    pos += 1 + comp_len;

    // Extensions
    if (pos + 2 > len) return "";
    int ext_len = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    int ext_end = pos + ext_len;
    if (ext_end > len) return "";

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
        uint16_t ext_size = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;

        if (ext_type == 0x00) { // SNI
            if (pos + 5 > ext_end) return "";
            int sni_list_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            uint8_t name_type = data[pos++];
            int name_len = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (pos + name_len > ext_end) return "";
            return std::string((const char*)(data + pos), name_len);
        }
        pos += ext_size;
    }
    return "";
}

uint16_t calc_checksum(uint16_t* data, int len) {
    uint32_t sum = 0;
    while (len > 1) {
        sum += *data++;
        len -= 2;
    }
    if (len == 1) sum += *(uint8_t*)data;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

Mac get_mac(const std::string& iface) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}


void send_rst_to_server(pcap_t* handle, const EthHdr* eth, const IpHdr* ip, const TcpHdr* tcp, int payload_len) {
    int ip_len = ip->header_len();
    int tcp_len = tcp->header_len();
    int total_len = sizeof(EthHdr) + ip_len + tcp_len;

    uint8_t pkt[1500] = {};
    EthHdr* eth_new = (EthHdr*)pkt;
    *eth_new = *eth;
    eth_new->smac_ = local_mac;

    IpHdr* ip_new = (IpHdr*)(pkt + sizeof(EthHdr));
    std::memcpy(ip_new, ip, ip_len);
    ip_new->sip_ = ip->sip_;
    ip_new->dip_ = ip->dip_;
    ip_new->ttl = ip->ttl;
    ip_new->total_length = htons(ip_len + tcp_len);
    ip_new->checksum = 0;
    ip_new->checksum = calc_checksum((uint16_t*)ip_new, ip_len);

    TcpHdr* tcp_new = (TcpHdr*)((uint8_t*)ip_new + ip_len);
    std::memcpy(tcp_new, tcp, tcp_len);
    tcp_new->sport_ = tcp->sport_;
    tcp_new->dport_ = tcp->dport_;
    tcp_new->seq_ = htonl(ntohl(tcp->seq_) + payload_len);
    tcp_new->flags_ = TcpHdr::RST | TcpHdr::ACK;
    tcp_new->win_ = 0;
    tcp_new->urp_ = 0;
    tcp_new->sum_ = 0;

    pseudo_header phdr = {};
    phdr.source_address = ip_new->sip_;
    phdr.dest_address = ip_new->dip_;
    phdr.protocol = IPPROTO_TCP;
    phdr.tcp_length = htons(tcp_len);

    std::vector<uint8_t> buf(sizeof(phdr) + tcp_len);
    std::memcpy(buf.data(), &phdr, sizeof(phdr));
    std::memcpy(buf.data() + sizeof(phdr), tcp_new, tcp_len);
    tcp_new->sum_ = calc_checksum((uint16_t*)buf.data(), buf.size());

    pcap_sendpacket(handle, pkt, total_len);
}

void send_rst_to_client(const IpHdr* ip, const TcpHdr* tcp, int payload_len) {
    int ip_len = ip->header_len();
    int tcp_len = tcp->header_len();
    int total_len = ip_len + tcp_len;

    uint8_t buffer[1500] = {};
    IpHdr* ip_new = (IpHdr*)buffer;
    std::memcpy(ip_new, ip, ip_len);
    ip_new->sip_ = ip->dip_;
    ip_new->dip_ = ip->sip_;
    ip_new->ttl = ip->ttl;
    ip_new->total_length = htons(total_len);
    ip_new->checksum = 0;
    ip_new->checksum = calc_checksum((uint16_t*)ip_new, ip_len);

    TcpHdr* tcp_new = (TcpHdr*)(buffer + ip_len);
    std::memcpy(tcp_new, tcp, tcp_len);
    tcp_new->sport_ = tcp->dport_;
    tcp_new->dport_ = tcp->sport_;
    tcp_new->seq_ = tcp->ack_;
    tcp_new->ack_ = tcp->seq_;
    tcp_new->flags_ = TcpHdr::RST | TcpHdr::ACK;
    tcp_new->win_ = 0;
    tcp_new->urp_ = 0;
    tcp_new->sum_ = 0;

    pseudo_header phdr = {};
    phdr.source_address = ip_new->sip_;
    phdr.dest_address = ip_new->dip_;
    phdr.protocol = IPPROTO_TCP;
    phdr.tcp_length = htons(tcp_len);

    std::vector<uint8_t> pseudo(tcp_len + sizeof(pseudo_header));
    std::memcpy(pseudo.data(), &phdr, sizeof(phdr));
    std::memcpy(pseudo.data() + sizeof(phdr), tcp_new, tcp_len);
    tcp_new->sum_ = calc_checksum((uint16_t*)pseudo.data(), pseudo.size());

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        return;
    }
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sock);
        return;
    }

    sockaddr_in sin = {};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip_new->dip_;
    if (sendto(sock, buffer, total_len, 0, (sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("sendto");
    }

    close(sock);
}

int main(int argc, char* argv[]) {
    if (argc != 3) { usage(); return -1; }
    std::string dev = argv[1], pattern = argv[2];
    local_mac = get_mac(dev);
    std::map<Key, std::string> segments;
    std::map<Key, time_t> blockedFlows;  // RST 감시용 키 저장소
    const int BLOCK_TTL = 5; // 5초간 RST 반복 전송

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1, errbuf);
    if (!handle) return -1;

    struct pcap_pkthdr* header;
    const u_char* pkt;

    while (true) {
        int res = pcap_next_ex(handle, &header, &pkt);
        if (res != 1) continue;

        const EthHdr* eth = (EthHdr*)pkt;
        if (ntohs(eth->type_) != EthHdr::Ip4) continue;
        const IpHdr* ip = (IpHdr*)(pkt + sizeof(EthHdr));
        if (ip->protocol != IpHdr::TCP) continue;

        int ip_len = ip->header_len();
        const TcpHdr* tcp = (TcpHdr*)((uint8_t*)ip + ip_len);
        int tcp_len = tcp->header_len();

        int total_len = ntohs(ip->total_length);
        int payload_len = total_len - ip_len - tcp_len;
        if (payload_len <= 0) continue;

        const uint8_t* data = (const uint8_t*)((uint8_t*)tcp + tcp_len);

        Key key{ip->sip_, ip->dip_, ntohs(tcp->sport_), ntohs(tcp->dport_)};

        // ✅ 이미 차단 중인 연결 키인지 확인
        auto it = blockedFlows.find(key);
        if (it != blockedFlows.end()) {
            if (time(nullptr) - it->second <= BLOCK_TTL) {
                std::cout << "[DEBUG] RST repeat for blocked key: "
                          << ip->sip() << ":" << ntohs(tcp->sport_) << " -> "
                          << ip->dip() << ":" << ntohs(tcp->dport_) << std::endl;
                send_rst_to_server(handle, eth, ip, tcp, payload_len);
                send_rst_to_client(ip, tcp, payload_len);
                continue;
            } else {
                blockedFlows.erase(it); // TTL 만료된 키 제거
            }
        }

        // TLS Client Hello 인지 확인
        if (data[0] != 0x16 || data[5] != 0x01) continue;

        std::string& buf = segments[key];
        buf.append((char*)data, payload_len);

        std::cout << "[DEBUG] Received TLS data for key: "
            << ip->sip() << ":" << ntohs(tcp->sport_) << " -> "
            << ip->dip() << ":" << ntohs(tcp->dport_) << " (" << buf.size() << " bytes)" << std::endl;

        if (buf.size() >= 6 && buf[0] == 0x16 && buf[5] == 0x01) {
            std::string sni = extract_sni((const uint8_t*)buf.data(), buf.size());
            if (!sni.empty()) {
                std::cout << "[DEBUG] Extracted SNI: " << sni << std::endl;
                if (sni.find(pattern) != std::string::npos) {
                    std::cout << "Blocking TLS SNI: " << sni << std::endl;
                    std::cout << "[DEBUG] Sending RST to server " << ip->dip() << ":" << ntohs(tcp->dport_) << std::endl;
                    std::cout << "[DEBUG] Sending RST to client " << ip->sip() << ":" << ntohs(tcp->sport_) << std::endl;

                    send_rst_to_server(handle, eth, ip, tcp, payload_len);
                    send_rst_to_client(ip, tcp, payload_len);

                    blockedFlows[key] = time(nullptr);  // 감시 시작 시간 기록
                    segments.erase(key); // 현재 버퍼 제거
                }
            }
        }
    }

    pcap_close(handle);
    return 0;
}

