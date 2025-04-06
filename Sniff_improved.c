#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>


/* Ethernet header */
struct ethheader {
  u_char  ether_dhost[6]; /* destination host address */
  u_char  ether_shost[6]; /* source host address */
  u_short ether_type;     /* protocol type (IP, ARP, RARP, etc) */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address
  struct  in_addr    iph_destip;   //Destination IP address
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, // 패킷 처리하는 함수
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet; // 패킷의 제일 앞부분을 Ethernet 헤더 구조체로 해석

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 은 IP v4 타입
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); // Ethernet 헤더 다음 위치부터 IP 헤더로 읽음

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));    

    /* determine protocol */
    switch(ip->iph_protocol) {                                 
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}

int main()
{
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
