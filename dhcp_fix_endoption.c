/*
 * dhcp_fix_endoption.c
 * Compile: gcc --std=c99 -Wall dhcp_fix_endoption.c -o dhcp_fix_endoption
 * Norbert Matzke, 2026-02-22
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_OPTIONS_SIZE 312

#pragma pack(push,1)
struct dhcp_packet {
    uint8_t  op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t  chaddr[16];
    uint8_t  sname[64];
    uint8_t  file[128];
    uint32_t magic_cookie;
    uint8_t  options[DHCP_OPTIONS_SIZE];
};
#pragma pack(pop)

void hexdump(const uint8_t *buf, int len)
{
    for (int i = 0; i < len; i += 16) {
        printf("%04x  ", i);
        for (int j = 0; j < 16 && i + j < len; j++)
            printf("%02x ", buf[i + j]);
        printf("\n");
    }
}

void print_mac(const uint8_t *mac, int len)
{
    for (int i = 0; i < len; i++)
        printf("%02x%s", mac[i], (i == len - 1) ? "" : ":");
}

enum reqtype {		// option 53 DHCP Message Type
	DHCPDISCOVER = 1,
	DHCPOFFER,
	DHCPREQUEST,
	DHCPDECLINE,
	DHCPACK,
	DHCPNAK,
	DHCPRELEASE,
	DHCPINFORM,
};

static int
is_client_req(int req_type)
{
	switch (req_type) {
	case DHCPDISCOVER:
	case DHCPREQUEST:
	case DHCPDECLINE:
	case DHCPRELEASE:
	case DHCPINFORM:
		return 1;
	}
	return 0;
}

static const char*
req_name(int req_type)
{
	switch (req_type) {
	case DHCPDISCOVER:
		return "DHCPDISCOVER";
		break;
	case DHCPOFFER:
		return "DHCPOFFER";
		break;
	case DHCPREQUEST:
		return "DHCPREQUEST";
		break;
	case DHCPDECLINE:
		return "DHCPDECLINE";
		break;
	case DHCPACK:
		return "DHCPACK";
		break;	
	case DHCPNAK:
		return "DHCPNAK";
		break;	
	case DHCPRELEASE:
		return "DHCPRELEASE";
		break;
	case DHCPINFORM:
		return "DHCPINFORM";
		break;
	}
	return "<unknown>";
}

static int
parse_options(struct dhcp_packet *p, unsigned p_opt_len,
	char *hostname, size_t hlen, struct in_addr *req_ip, int *req_type,
	int *have_end_opt )
{
    unsigned i = 0;
    hostname[0] = 0;
    req_ip->s_addr = 0;
	if (have_end_opt) *have_end_opt = 0;
	if (req_type) *req_type = -1;

    while (i < p_opt_len) {
        uint8_t opt = p->options[i];
        if (opt == 0xff) {
			if (have_end_opt) *have_end_opt = 1;
			break;
		}
        if (opt == 0x00) { // pad option
			i++;
			continue;
		}
        if (i + 1 >= p_opt_len) {
			// end of options -- end of DHCP message payload
			break;
		}

        uint8_t olen = p->options[i+1];
        if (i + 2 + olen > p_opt_len) {
			printf("ERROR: too long option item ...\n");
			return -2;
		}
        const uint8_t *val = &p->options[i+2];
		i += 2 + olen;

        if (opt == 53 && olen == 1) {
			if (req_type) *req_type = val[0];
		}

        if (opt == 12) {
			if (olen < hlen) { // Hostname
				memcpy(hostname, val, olen);
				hostname[olen] = 0;
			} else {
				printf("ERROR, BUG: hostname buffer too small\n");
				return -10;
			}
        }

        if (opt == 50 && olen == 4) { // Requested IP
            memcpy(req_ip, val, 4);
        }
		
		// ... TODO
    }
	// TODO: if found 'option overload' (52) we must continue option parsing in
	// 'sname' and 'file' fields. Recursion required -- but as this ugly source
	// is based on ChatGPT generated one, it would require complete refactoring ... 
    return 0;
}

static int
print_dhcp_header(struct dhcp_packet *p)
{
	printf("Client MAC: ");
	print_mac(p->chaddr, p->hlen);
	printf("\n");

	printf("XID: 0x%08x\n", ntohl(p->xid));
	printf("Flags: 0x%04x\n", ntohs(p->flags));
	printf("hops: %u\n", (unsigned)p->hops);

	//printf("ciaddr: %s\n", inet_ntoa(*(struct in_addr*)&p->ciaddr));
	//printf("yiaddr: %s\n", inet_ntoa(*(struct in_addr*)&p->yiaddr));
	//printf("siaddr: %s\n", inet_ntoa(*(struct in_addr*)&p->siaddr));
	//printf("giaddr: %s\n", inet_ntoa(*(struct in_addr*)&p->giaddr));
	return 0;
}
		
static int
get_socket_bind(unsigned short port, int snd_broadcast)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
		perror("socket");
		return -1;
	}

    const int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	if (snd_broadcast) {
		setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
	}
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return -2;
    }
	return sock;
}

struct in_pktinfo {
	unsigned int   ipi_ifindex;  // Interface index
	struct in_addr ipi_spec_dst; // Local address
	struct in_addr ipi_addr;     // Header Destination address
};
				  
int main(int argc, char *argv[])
{
	int rc;
	int do_hexdump = 0;
	int printall = 1;

    int rcv_sock = get_socket_bind(67, 0);
	int snd_sock = get_socket_bind(68, 1);

	if (rcv_sock < 0 || snd_sock <0) {
		printf("ERROR: failed to get sockets, terminating ...\n");
		return 2;
	}
	
	// we want detailed info for recevied packets (destination address)
	// include struct in_pktinfo in the message "ancilliary" control data
	const int yes = 1;
	rc = setsockopt(rcv_sock, IPPROTO_IP, IP_PKTINFO, &yes, sizeof(yes));
	if (rc < 0) {
		perror("");
		printf("ERROR: setsockopt(IPPROTO_IP, IP_PKTINFO) failed, terminating ...\n");
		return 3;
	}

    printf("Listening for malformed DHCP DISCOVER packets on UDP port 67: If they don't have 'end option', append\n"
		"it and rebroadcast the packet. So we can still use Mikrotik RouterOS DHCP server in our network ...\n");

    uint8_t buf[sizeof (struct dhcp_packet)];
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(rcv_sock, &fds);

		struct timeval timeout = {0};
		timeout.tv_sec = 10;
			
        if (select(rcv_sock + 1, &fds, NULL, NULL, &timeout) < 0) {
            perror("select");
            exit(1);
        }

        if (!FD_ISSET(rcv_sock, &fds)) {
			printf(".");
			fflush(stdout);
            continue;
		}

/*		This is the simple way -- but we do not get the target address of the package, i.e.
		the correct broadcast IP addresss.  So do it the complicated way using recvmsg()
		
        struct sockaddr_in src;
        const socklen_t slen = sizeof(src);
        int n = recvfrom(rcv_sock, buf, sizeof buf, 0,
                         (struct sockaddr *)&src, &slen);
*/
		char cmbuf[512];
		struct iovec iobuf = { buf, sizeof buf };
		struct sockaddr_in src;
		struct msghdr mh = {
			.msg_name = &src,
			.msg_namelen = sizeof(src),
			.msg_iov = &iobuf,
			.msg_iovlen = 1,
			.msg_control = cmbuf,
			.msg_controllen = sizeof(cmbuf),
		};
		int n = recvmsg(rcv_sock, &mh, 0);

		// get destination address and possibly other message related data
		int have_addr = 0;
		struct sockaddr_in dst_addr = {0};
		struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
		for (; cmsg != 0; cmsg = CMSG_NXTHDR(&mh, cmsg)) {
			// ignore other control headers
			if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_PKTINFO) {
				continue;
			}
			struct in_pktinfo *pi = (struct in_pktinfo *)CMSG_DATA(cmsg);
			dst_addr.sin_family = AF_INET;
			dst_addr.sin_port = htons(67);
			dst_addr.sin_addr = pi->ipi_addr;
			have_addr = 1;
		}
		if (!have_addr) {
			printf("WARNING: missing to/from address, skipping msg\n");
			continue;
		}

		const unsigned dhcp_hdr_sz = sizeof (struct dhcp_packet) - DHCP_OPTIONS_SIZE;
        if (n <= 0 || n < dhcp_hdr_sz) {
			printf("\nWARN: skipped short packet, sz=%i\n", n );
            continue;
		}
        struct dhcp_packet *p = (struct dhcp_packet *)buf;
		
		unsigned p_total_size = n;
		unsigned p_opt_size = p_total_size - dhcp_hdr_sz;
		
        if (ntohl(p->magic_cookie) != DHCP_MAGIC_COOKIE) {
			printf("\nWARN: skipped packet without DHCP magic cookie\n");
            continue;
		}
		if (p->op != 1) { // 1=BOOTREQUEST, 2=BOOTREPLY
			// not a Client --> Server message
			continue;
		}
		if (p->htype != 1 || p->hlen != 6) {
			continue;   // not Ethernet or not MAC Addr length 6 bytes
		}

		char hostname[256] = {'\0'};
		struct in_addr req_ip = {0};
		int req_type = -1;
		int has_end_opt = 0;
		rc = parse_options(p, p_opt_size, hostname, sizeof(hostname), &req_ip, &req_type, &has_end_opt);
		if (rc<0) {
			printf("WARNING: DHCP parse_options() failed on message, rc=%i\n", rc);
			continue;
		}
		if (req_type < 0) {
			printf("WARNING: DHCP msg without mandatory option 53\n");
			continue;
		}
		
		if (printall && req_type == DHCPDISCOVER) {
			printf("\n================ DHCP %s ================\n", req_name(req_type) );
			printf("From %s:%u\n", inet_ntoa(src.sin_addr), (unsigned)ntohs(src.sin_port));	
			printf("To   %s:%u\n", inet_ntoa(dst_addr.sin_addr), (unsigned)ntohs(dst_addr.sin_port));	
			print_dhcp_header(p);
			
			if (hostname[0]) {
				printf("Hostname (opt12): %s\n", hostname);
			}
			printf("Packet length: %d bytes\n", p_total_size);
			if (req_ip.s_addr) {
				printf("Requested IP (opt50): %s\n", inet_ntoa(req_ip));
			}
			if (do_hexdump) {
				printf("---------------- HEX DUMP ----------------\n");
				hexdump((uint8_t *)p, p_total_size);
			}
			printf("==========================================\n");
		}

		if (is_client_req(req_type) && !has_end_opt) {
			// append the "end option" and do re-broadcast of the modified packet
				
			if (ntohs(src.sin_port) != 68) {
				printf("WARNING: won't rebroadcast bcs. sender did not use sender port 68\n");
				continue;
			}
			if (p->hops > 1) {  // prevent loop by limiting 'hops'
				printf("WARNING: won't rebroadcast bcs. hops already >1\n");
				continue;			
			}

			printf("\n================ DHCP %s FIXUP ============\n", req_name(req_type) );
			print_dhcp_header(p);
			if (hostname[0]) {
				printf("Hostname (opt12): '%s'\n", hostname);
			}
			printf("Packet length: %d bytes\n", p_total_size);
			if (do_hexdump) {
				printf("---------------- HEX DUMP ----------------\n");
				hexdump((uint8_t *)p, p_total_size);
			}

			p->hops++;  // be honest, increment hops count
			// just append 'end option' to option field or replace last pad option
			if (p_opt_size < DHCP_OPTIONS_SIZE) {
				p->options[p_opt_size++] = 0xFF;
				++p_total_size;
			} else if (p->options[p_opt_size - 1] == 0x00) {
				p->options[p_opt_size - 1] = 0xFF;
			} else {
				printf("ERROR: cannot append 'end option' as there is no space left, sorry\n");
				continue;
			}
			// enable broadcast flag ???
			// p->flags |= htons(0x8000);
			
			rc = sendto(snd_sock, (void *)p, p_total_size, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
			if (rc < 0) {
				perror("sendto");
				printf("ERROR: rebroadcast sendto() failed\n");
			} else {
				printf("====== FIXED %s RETRANSMITTED, %i octets ======\n",
					req_name(req_type), rc);
			}
		}
    }
	
	close(snd_sock);
	close(rcv_sock);
	printf("FINISHED\n");
	return 0;
}
