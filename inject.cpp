#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <cstdint>
#include <cmath>
#include <iostream>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <time.h>

   int nanosleep(const struct timespec *req, struct timespec *rem);

#include "process_packet.h"

using namespace std;

double delay = 0;

// https://home.regit.org/netfilter-en/using-nfqueue-and-libnetfilter_queue/
// http://www.netfilter.org/projects/libnetfilter_queue/doxygen/nfqnl__test_8c_source.html
// https://github.com/irontec/netfilter-nfqueue-samples/blob/master/sample-helloworld.c

static void print_pkt(struct nfq_data *tb)
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
    for (i = 0; i < hlen-1; i++) {
      printf("%02x:", hwph->hw_addr[i]);
    }
    printf("%02x ", hwph->hw_addr[hlen-1]);
  }

  mark = nfq_get_nfmark(tb);
  if (mark) {
    printf("mark=%u ", mark);
  }

  ifi = nfq_get_indev(tb);
  if (ifi) {
    printf("indev=%u ", ifi);
  }

  ifi = nfq_get_outdev(tb);
  if (ifi) {
    printf("outdev=%u ", ifi);
  }
  ifi = nfq_get_physindev(tb);
  if (ifi) {
    printf("physindev=%u ", ifi);
  }

  ifi = nfq_get_physoutdev(tb);
  if (ifi) {
    printf("physoutdev=%u ", ifi);
  }

  ret = nfq_get_payload(tb, &data);
  if (ret >= 0) {
    printf("payload_len=%d ", ret);
    //processPacketData (data, ret);
  }
  fputc('\n', stdout);
  //ProcessPacket(data, ret);

  struct timespec req;
  req.tv_sec = floor(delay);
  req.tv_nsec = floor((delay - floor(delay))*1000000000);

  ret = nanosleep(&req, nullptr);
  if (ret < 0) {
    cerr << "error sleeping" << endl;
  }

  return;
}


/* Definition of callback function */
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
  print_pkt(nfa);
  uint32_t id;
  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfa); 
  id = ntohl(ph->packet_id);
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); /* Verdict packet */
}
 


int main(int argc, char *argv[]) {
  assert(argc >= 2);
  int queueNum = atoi(argv[1]);
  cout << "using queue num " << queueNum << endl;
  if (argc >= 3) {
    delay = atof(argv[2]);
  }
  cout << "delaying " << delay << " seconds" << endl;

  struct nfq_handle *h;
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

  /* Set callback function */
  cout << "binding this socket to queue " << queueNum << endl;
  struct nfq_q_handle *qh = nfq_create_queue(h,  queueNum, &cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  int fd = nfq_fd(h);
  int rv;
  char buf[4096];
  while (true) {
      //cout << "top of loop" << endl;
      if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
          //cout << "about to handle" << endl;
          nfq_handle_packet(h, buf, rv); /* send packet to callback */
          continue;
      }
  }
  return 0;
}
