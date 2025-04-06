#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <ctype.h>   // for isprint()

#include "myheader.h"  // Ethernet/IP/TCP header 구조체 정의된 헤더 파일

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    // libcap가 캡쳐해온 packet 데이터를 ethheader 구조체로 해석한다

    if (ntohs(eth->ether_type) == 0x0800) {  // IP v4 패킷만 처리
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        // Ethernet 헤더 다음 위치부터 IP 헤더로 읽음

        if (ip->iph_protocol == IPPROTO_TCP) {  // TCP만 처리
            int ip_header_len = ip->iph_ihl * 4 // Ip 헤더 계산
            struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
            // IP 헤더는 가변적이기 때문에 실제 바이트 단위의 길이를 계산 후 TCP 헤더 시작 위치를 결정

            printf("\n=== TCP Packet ===\n");
            printf("From MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", // src mac
                   eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                   eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("To MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n", // dst mac
                   eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                   eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("From IP: %s\n", inet_ntoa(ip->iph_sourceip)); // src ip
            printf("To IP  : %s\n", inet_ntoa(ip->iph_destip)); // dst ip

            printf("Src port: %u\n", ntohs(tcp->tcp_sport)); // src port
            printf("Dst port: %u\n", ntohs(tcp->tcp_dport)); // dst port

            // Payload (Message) 출력
            int tcp_header_len = TH_OFF(tcp) * 4; // 실제 바이트 단위 TCP 헤더 길이 추출
            int total_len = ntohs(ip->iph_len); // IP 헤더 안에 있는 총 패킷 길이 추출
            int payload_len = total_len - ip_header_len - tcp_header_len;
            // IP 헤더 길이와 TCP 헤더 길이를 뺀 값 = PAYLOAD(메세지)

            if (payload_len > 0) { // 메세지 없으면 출력 X
                const u_char *payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
                // 실제로 payload가 시작하는 위치를 포인터로 지정하고
                printf("Payload (%d bytes):\n", payload_len); // PAYLOAD(메세지) 출력

                // 최대 256 바이트까지만 출력
                for (int i = 0; i < payload_len && i < 256; i++) {
                    if (isprint(payload[i]))
                        printf("%c", payload[i]);
                    else
                        printf(".");
                }
                printf("\n");
            } else {
                printf("No payload.\n");
            }
        }
    }
}

int main() {
    pcap_t *handle; // 패킷 캡처 세션을 저장함
    char errbuf[PCAP_ERRBUF_SIZE]; // 에러메시지 저장할 버퍼선언
    struct bpf_program fp; // BPF 필터를 컴파일하는 데 사용하는 구조체 선언
    char filter_exp[] = "icmp"; // 캡처할 패킷 지정
    bpf_u_int32 net; // 네트워크 저장 변수 net 선언

    // Step 1: Open live pcap session on NIC with name enp0s3
    // enp0s3 네트워크 인터페이스에서 실시간 패킷캡처 세션을 열음
    // 모든 버퍼를 캡처 (1) 타임아웃은 1초 (1000) 에러 메세지는 errbuf에 저장
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Step 2: Compile filter_exp into BPF psuedo-code
    // filter_exp을 컴파일해서 BPF 포맷으로 변환
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) !=0) { // 위에서 컴파일한 fp를 pcap 세션에 적용
        pcap_perror(handle, "Error:"); // 실패시 에러
        exit(EXIT_FAILURE); // 종료
    }

    // Step 3: Capture packets
    // 패킷 캡쳐
    pcap_loop(handle, -1, got_packet, NULL); // (-1) 옵션으로 종료시킬때까지 무한히 패킷캡쳐

    pcap_close(handle);   //Close the handle
    return 0;
}
