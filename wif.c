#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
// #include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
// #include <netinet/in.h>
#include <arpa/inet.h>

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

char *mac_ntoa(u_char *d);

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
}

/*
 * dissect/print packet
 */

typedef struct {
	char* mac;
	char* talks_to;
	long long count;
} mac_and_count;

int compare_macs(const void *a, const void *b) {
	mac_and_count *x = (mac_and_count *) a;
	mac_and_count *y = (mac_and_count *) b;
	return (x->count > y->count) - (x->count < y->count);
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 0;                   /* packet counter */
	// static char* macs[1000];
	// static int macs_count[1000];
	static mac_and_count mc[1000];
	static int mc_len = 0;
	static int largest_pkt;
	static int smallest_pkt;

	static long long total;
	u_char *curr = (u_char *)(packet + packet[2]); // skip radiotap

	if ((curr[1] & 0b00000011) != 2) return; // god i hope this works: filter for 10 ds status -> from ds but not to ds

	count++;

	printf("\nPacket number %d:\n", count);

	printf("Length: %d\n", header->len - packet[2]);

	if (count == 1) {
		smallest_pkt = largest_pkt = header->len - packet[2];
	} else {
		if (header->len - packet[2] >  largest_pkt)  largest_pkt = header->len - packet[2];
		if (header->len - packet[2] < smallest_pkt) smallest_pkt = header->len - packet[2];
	}

	// if (count == 5) {
	// 	exit(3);
	// }

	printf("mac1: %s\n", mac_ntoa(curr+4)); // the receiver, which is what we want to track
	printf("mac2: %s\n", mac_ntoa(curr+6+4)); // BSSID
	printf("mac3: %s\n", mac_ntoa(curr+12+4)); // source. empirically usually the router mac address

	print_payload(curr, header->len - packet[2]);

	total += header->len - packet[2];

	// tally up the packet length for each mac
	for (int i = 0; i < 1000; i++)
	{
		if (mc[i].mac == NULL)
		{
			mc[i].mac = (char *)malloc(18);
			strcpy(mc[i].mac, mac_ntoa(curr+4));

			mc[i].count = header->len - packet[2];

			mc[i].talks_to = (char *)malloc(18);
			strcpy(mc[i].talks_to, mac_ntoa(curr+12+4));
			mc_len++;
			break;
		}
		if (strcmp(mc[i].mac, mac_ntoa(curr+4)) == 0)
		{
			mc[i].count += header->len - packet[2];
			strcpy(mc[i].talks_to, mac_ntoa(curr+12+4));
			break;
		}
	}

	qsort (mc, mc_len, sizeof(*mc), compare_macs);

	// print out the macs and their tallies
	for (int i = 0; i < 1000; i++)
	{
		if (mc[i].mac == NULL) break;
		//printf("%s: %d\n", macs[i], macs_count[i]);
		printf("%s (last talked to %s): %0.2f%%\n", mc[i].mac, mc[i].talks_to, ((double)mc[i].count)/((double)total) * 100);
	}

	printf("Smallest packet size: %d\n", smallest_pkt);
	printf("Largest packet size:  %d\n", largest_pkt);
}

int main()
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	/* packet capture handle */

// and (not host 192.168.86.27)
	// char filter_exp[] = "tcp src portrange 0-1023 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";		/* filter expression [3] */
	// char filter_exp[] = "type mgt subtype probe-req"; // subtype probe-req		/* filter expression [3] */
	char filter_exp[] = "(type data) or (type ctl) or (type mgt)";//subtype data";		/* filter expression [3] */
	// char filter_exp[] = "type mgt subtype beacon";
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	// int num_packets = 10000;			/* number of packets to capture */

	/* find a capture device if not specified on command-line */
	// dev = pcap_lookupdev(errbuf);
	// if (dev == NULL) {
	// 	fprintf(stderr, "Couldn't find default device: %s\n",
	// 	    errbuf);
	// 	exit(EXIT_FAILURE);
	// }∏

	dev = "en0";

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	// printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	// /* open capture device */
	// handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	// if (handle == NULL) {
	// 	fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	// 	exit(EXIT_FAILURE);
	// }

	pcap_t* handle = pcap_create(dev, errbuf);
	if (handle == NULL)
	{
		printf("pcap_create failed:%s\n", errbuf);
		return 3; // or exit or return an error code or something
	}

	if(pcap_set_rfmon(handle,1)==0 )
	{
		printf("monitor mode enabled\n");
	}
	pcap_set_snaplen(handle, 65535);  // Set the snapshot length to 65535
	pcap_set_promisc(handle, 1); // Turn promiscuous mode off
	pcap_set_timeout(handle, 512); // Set the timeout to 512 milliseconds
	const int status = pcap_activate(handle);
	if (status < 0)
	{
		printf("pcap_activate failed: %s\n", pcap_geterr(handle));
		return 3; // or exit or return an error code or something
	}

	// if (pcap_can_set_rfmon(handle) == 0) {
    //     fprintf(stderr, "Monitor mode not supported on %s\n", dev);
    //     return 3;
    // }

	// if(pcap_set_rfmon(handle,1)==0 )
	// {
	// 	printf("monitor mode enabled\n");
	// }

	/* make sure we're capturing on an Ethernet device [2] */
	// if (pcap_datalink(handle) != DLT_EN10MB) {
	// 	fprintf(stderr, "%s is not an Ethernet\n", dev);
	// 	exit(EXIT_FAILURE);
	// }

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	printf("started!\n");

	/* now we can set our callback function */
	pcap_loop(handle, -1, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}


char *mac_ntoa(u_char *d)
{
	static char str[18];
	sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
		d[0], d[1], d[2], d[3], d[4], d[5]);
	return str;
}