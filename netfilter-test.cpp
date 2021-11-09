#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>      /* for NF_ACCEPT */
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char* malicious_site;
int help=0;
void is_malicious(u_char* buf, int size);
static u_int32_t print_pkt (struct nfq_data *tb)
{
   int id = 0;
   struct nfqnl_msg_packet_hdr *ph;
   struct nfqnl_msg_packet_hw *hwph;
   u_int32_t mark,ifi;
   int ret;
   unsigned char *data;

   ph = nfq_get_msg_packet_hdr(tb);
   if (ph) {
      id = ntohl(ph->packet_id);
      printf("hw_protocol=0x%04x hook=%u id=%u ",
         ntohs(ph->hw_protocol), ph->hook, id);
   }

   hwph = nfq_get_packet_hw(tb);
   if (hwph) {
      int i, hlen = ntohs(hwph->hw_addrlen);

      printf("hw_src_addr=");
      for (i = 0; i < hlen-1; i++)
         printf("%02x:", hwph->hw_addr[i]);
      printf("%02x ", hwph->hw_addr[hlen-1]);
   }

   mark = nfq_get_nfmark(tb);
   if (mark)
      printf("mark=%u ", mark);

   ifi = nfq_get_indev(tb);
   if (ifi)
      printf("indev=%u ", ifi);

   ifi = nfq_get_outdev(tb);
   if (ifi)
      printf("outdev=%u ", ifi);
   ifi = nfq_get_physindev(tb);
   if (ifi)
      printf("physindev=%u ", ifi);

   ifi = nfq_get_physoutdev(tb);
   if (ifi)
      printf("physoutdev=%u ", ifi);

   ret = nfq_get_payload(tb, &data);
   if (ret >= 0){
        printf("payload_len=%d\n", ret);
        is_malicious(data,ret);
    }


   fputc('\n', stdout);

   return id;
}

void is_malicious(u_char* buf, int size) {
   struct ip* ip_header = (struct ip *)(buf);
   int ip_len = ip_header->ip_hl << 2;
    struct tcphdr* tcp_header = (struct tcphdr *)(buf + ip_len);
   int tcp_len = tcp_header->th_off << 2;
        char* payload = (char *)(buf + ip_len + tcp_len);
   int payload_len = ntohs(ip_header->ip_len) - (tcp_len +ip_len);
   char temp[100];
    int check=0;
   int jump=0;
    int start=0;
    int end=0;
    if (ip_header->ip_p==IPPROTO_TCP){

    for (int i = 0; i < payload_len; i++){
        if (payload[i] == 0x0d && payload[i+1] == 0x0a){
            if(check==1){
                end=i+1;
                jump=1;
                break;
            }
         start=i+2;
            check++;
         }
       }
   }
   if(jump==1){
      printf("start=%d\n",start);
      printf("end=%d\n",end);
      strncpy(temp,&payload[start],end-start+1);
      printf("temp=%s\n",temp);
      if(strstr(temp,malicious_site) != NULL){
         help=1;
         printf("drop");
      }
   }
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
         struct nfq_data *nfa, void *data)
{
   u_int32_t id = print_pkt(nfa);
   printf("entering callback\n");
    if(help==1) {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
   else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
    if ( argc != 2 ) {
      printf("Usage: netfilter-test <host>\n");
      printf("sample : netfilter-test test.gilgil.net\n");
      exit(1);
   }
   struct nfq_handle *h;
   struct nfq_q_handle *qh;
   struct nfnl_handle *nh;
   int fd;
   int rv;
   char buf[4096] __attribute__ ((aligned));

    char site[100]="Host: ";
    strcat(site, argv[1]);
    strcat(site, "\r\n");
   malicious_site = site;
   printf("malicious_site=%s",malicious_site);
   printf("strlen=%ld",strlen(malicious_site));

   printf("opening library handle\n");
   h = nfq_open();
   if (!h) {
      fprintf(stderr, "error during nfq_open()\n");
      exit(1);
   }

   printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
   if (nfq_unbind_pf(h, AF_INET) < 0) {
      fprintf(stderr, "error during nfq_unbind_pf()\n");
      exit(1);
   }

   printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
   if (nfq_bind_pf(h, AF_INET) < 0) {
      fprintf(stderr, "error during nfq_bind_pf()\n");
      exit(1);
   }

   printf("binding this socket to queue '0'\n");
   qh = nfq_create_queue(h,  0, &cb, NULL);
   if (!qh) {
      fprintf(stderr, "error during nfq_create_queue()\n");
      exit(1);
   }

   printf("setting copy_packet mode\n");
   if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
      fprintf(stderr, "can't set packet_copy mode\n");
      exit(1);
   }

   fd = nfq_fd(h);

   for (;;) {
      if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
         printf("pkt received\n");
         nfq_handle_packet(h, buf, rv);
         continue;
      }
      /* if your application is too slow to digest the packets that
       * are sent from kernel-space, the socket buffer that we use
       * to enqueue packets may fill up returning ENOBUFS. Depending
       * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
       * the doxygen documentation of this library on how to improve
       * this situation.
       */
      if (rv < 0 && errno == ENOBUFS) {
         printf("losing packets!\n");
         continue;
      }
      perror("recv failed");
      break;
   }

   printf("unbinding from queue 0\n");
   nfq_destroy_queue(qh);

#ifdef INSANE
   /* normally, applications SHOULD NOT issue this command, since
    * it detaches other programs/sockets from AF_INET, too ! */
   printf("unbinding from AF_INET\n");
   nfq_unbind_pf(h, AF_INET);
#endif

   printf("closing library handle\n");
   nfq_close(h);

   exit(0);
}
