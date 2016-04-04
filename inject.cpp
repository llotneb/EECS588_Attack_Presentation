#include <cstdlib>
#include <cstdio>
#include <cassert>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <queue>
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <random>
#include <fstream>
#include <vector>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <netdb.h> 

#include "process_packet.h"

using namespace std;

double delay = 0;
double variation = 0;
double throttle = 0;
int numClients = 0;

struct Client {
  int sock;
  socklen_t clientLen;
  struct sockaddr_in addr;
  string username;
};
vector<Client> clients;
  

using uint64 = uint64_t;
using int64 = int64_t;
using uint32 = uint32_t;

struct WaitingPacket {
  uint32_t id;
  int length;
  unsigned char* data;
  int64 createdTime;

  WaitingPacket(uint32_t id, int length, unsigned char* data, int64 time) :
      id(id), length(length), data(data), createdTime(time) {
  }
};

struct ArrivedPacket {
  uint32 id;
  int length;
  unsigned char* data;
  int64 arrivedTime;

  ArrivedPacket(uint32 id, int length, unsigned char* data, int64 time) :
      id(id), length(length), data(data), arrivedTime(time) {
  }
};

queue<WaitingPacket> waitingPackets;
mutex waitingPacketsMutex;
condition_variable waitingPacketsCv;

queue<ArrivedPacket> arrivedPackets;
mutex arrivedPacketsMutex;
condition_variable arrivedPacketsCv;

random_device randomDevice;
mt19937 prng(randomDevice());
nfq_q_handle *queue_handle = (nfq_q_handle*)7;

int sockToServer;

char password[8] = "toritup";


//in microseconds
int64 getTime() {
  return chrono::time_point_cast<chrono::duration<int64, micro>>(chrono::system_clock::now()).time_since_epoch().count();
}

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
static int cb(nfq_q_handle *qh, nfgenmsg *nfmsg,
              nfq_data *nfa, void *data)
{
  print_pkt(nfa);
  uint32 id;
  struct nfqnl_msg_packet_hdr *ph;
  ph = nfq_get_msg_packet_hdr(nfa); 
  id = ntohl(ph->packet_id);
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); /* Verdict packet */
}

int cbAddToWaiting(nfq_q_handle *qh, nfgenmsg *nfmsg, 
                   nfq_data *nfa, void *passed_data) {
  int64 createdTime = getTime();
  queue_handle = qh;
  cout << "to wait packet has handle " << queue_handle << endl;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa); 
  uint32 id = ntohl(ph->packet_id);
  unsigned char* data;
  int length = nfq_get_payload(nfa, &data);
  waitingPacketsMutex.lock();
  waitingPackets.push(WaitingPacket(id, length, data, createdTime));
  waitingPacketsMutex.unlock();
  waitingPacketsCv.notify_one();
}

int cbDetect(nfq_q_handle *qh, nfgenmsg *nfmsg, 
             nfq_data *nfa, void *passed_data) {
  int64 arrivedTime = getTime();
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa); 
  uint32 id = ntohl(ph->packet_id);
  unsigned char* data;
  int length = nfq_get_payload(nfa, &data);
  arrivedPacketsMutex.lock();
  arrivedPackets.push(ArrivedPacket(id, length, data, arrivedTime));
  arrivedPacketsMutex.unlock();
  arrivedPacketsCv.notify_one();
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL); /* Verdict packet */
}


struct SentPacket {
  int length;
  int64 createdTime;
  int64 sentTime;

  SentPacket(int length, int64 createdTime, int64 sentTime) :
      length(length), createdTime(createdTime), sentTime(sentTime) {
  }

};

void sendPackets() {
  vector<SentPacket> sentPackets;
  int64 firstAdded = getTime();
  
  normal_distribution<> distribution(0.0, variation);

  while (true) {
    double jitter = distribution(prng);
    jitter = max(min(jitter, variation*3.0), -variation*3.0);
    int64 currentDelay = max(delay + jitter + throttle, 0.0)*1000000;

    unique_lock<mutex> lock(waitingPacketsMutex);
    while (waitingPackets.empty()) {
      waitingPacketsCv.wait(lock);
    } 
    int64 toWait = currentDelay - (getTime() - waitingPackets.front().createdTime);
    if (toWait > 0) {
      lock.unlock();
      this_thread::sleep_for(chrono::microseconds(toWait));
      lock.lock();
    }
    WaitingPacket toSend = waitingPackets.front();
    waitingPackets.pop();
    lock.unlock();

    int64 time = getTime();
    int ret = nfq_set_verdict(queue_handle, toSend.id, NF_ACCEPT, 0, NULL); /* Verdict packet */
    assert(ret >= 0);

    sentPackets.push_back(SentPacket(toSend.length, toSend.createdTime, time));
    if (sentPackets.size() >= 10 || (sentPackets.size() >= 2 && time - firstAdded >= 2*1000000)) {
      vector<int64> data;
      for (int i = 0; i < sentPackets.size(); ++i) {
        data.push_back(sentPackets[i].length);
        data.push_back(sentPackets[i].sentTime);
      }
      for (const Client& client : clients) {
        ret = write(client.sock, data.data(), data.size()*8);
        assert(ret == data.size()*8);
      }
      sentPackets.clear();
    } else if (sentPackets.size() == 1) {
      firstAdded = getTime();
    }
  }
  cout << "done with sendPackets" << endl;
}

void detectPackets() {
  vector<ArrivedPacket> seenPackets; // Packts that have fully arrived through tor
  vector<SentPacket> sentPackets; // Packet times of sent packets. The server sent us these times.
  int seenWritten = 0;
  int sentWritten = 0;

  int64 buffer[20];
  int haveAmount = 0;

  while (true) {
    while (true) {
      int ret = recv(sockToServer, (char*)buffer + haveAmount, 20*8, MSG_DONTWAIT);
      if (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      } else if (ret > 0) {
        haveAmount += ret;
        cout << "ret was " << ret << " haveAmount " << haveAmount << endl;
        for (int i = 0; i < haveAmount/16; i++) {
          sentPackets.push_back(SentPacket(buffer[i*2], 0, buffer[i*2+1]));
          cout << "new sent packet data " << sentPackets.back().length << endl;
        }
        memmove(buffer, (char*)buffer + (haveAmount/16)*16, (haveAmount/16)*16);
        haveAmount = haveAmount % 16;
      } else {
        perror("recv error");
        cerr << ret << ' ' << errno << endl;
        exit(1);
      }
      if (ret <= 0) {
        break;
      }
    }

    arrivedPacketsMutex.lock(); // arrived packets is just a temporary store of packets from tor
    while (!arrivedPackets.empty()) {
      seenPackets.push_back(arrivedPackets.front());
      arrivedPackets.pop();
      cout << "new packet seen " << seenPackets.back().length << endl;
    }
    arrivedPacketsMutex.unlock();

    ofstream ofsSeen("seenpackets.txt", ios_base::app);
    for (int i = seenWritten; i < seenPackets.size(); ++i) {
      ofsSeen << seenPackets[i].id << ',' << seenPackets[i].length << ',' << seenPackets[i].arrivedTime << '\n';
      ++seenWritten;
    }
    ofsSeen.close();

    ofstream ofsSent("sentpackets.txt", ios_base::app);
    for (int i = sentWritten; i < sentPackets.size(); ++i) {
      ofsSent << sentPackets[i].length << ',' << sentPackets[i].sentTime << '\n';
      ++sentWritten;
    }
    ofsSent.close();
    this_thread::sleep_for(chrono::milliseconds(500));
  }
}
  
  
  

void activateNFQ(int queueNum, 
              int (*cb)(struct nfq_q_handle*, struct nfgenmsg*, 
                        struct nfq_data*, void*)) {
  cout << "activating nfq" << endl;
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
  struct nfq_q_handle *qh = nfq_create_queue(h,  queueNum, cb, NULL);
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
  cout << "final packet handle loop" << endl;
  while (true) {
      //cout << "top of loop" << endl;
      if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
          //cout << "about to handle" << endl;
          nfq_handle_packet(h, buf, rv); /* send packet to callback */
          continue;
      }
  }
}

void setupSockToClient() {
  cout << "setting up sock to client(s)" << endl;
  int listeningSock;
  int portNum = 17666;
  struct sockaddr_in serverAddr;
  listeningSock = socket(AF_INET, SOCK_STREAM, 0);
  if (listeningSock < 0) {
    perror("ERROR opening socket");
    exit(1);
  }
  int enable = 1;
  if (setsockopt(listeningSock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    perror("setsockopt(SO_REUSEADDR) failed");
    exit(1);
  }
  memset(&serverAddr, sizeof(serverAddr), 0);
  serverAddr.sin_family = AF_INET;
  serverAddr.sin_addr.s_addr = INADDR_ANY;
  serverAddr.sin_port = htons(portNum);
  if (bind(listeningSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
    perror("error binding");
    exit(1);
  }
  listen(listeningSock, 5);

  while (clients.size() < numClients) {
    cout << "listening for client " << clients.size() + 1 << endl;
    Client client;
    client.clientLen = sizeof(client.addr);
    client.sock = accept(listeningSock, (struct sockaddr *)&client.addr, &client.clientLen);
    if (client.sock < 0) {
      perror("error accepting");
      exit(1);
    }
    char buffer[8];
    int ret = read(client.sock, buffer, 8);
    if (ret < 8) {
      perror("error getting password");
      exit(1);
    }
    buffer[7]= '\0';
    if (strcmp(buffer, password) != 0) {
      cerr << "wrong password, got " << buffer << endl;
      close(client.sock);
    } else {
      cout << "client " << clients.size() + 1 
           << " has connected from real ip " << inet_ntoa(client.addr.sin_addr) << endl;
      clients.push_back(client);
    }
  }

}

void setupSockToServer(const string& serverName) {
  cout << "setting up sock to server" << endl;
  int portNum = 17666;
  sockToServer = socket(AF_INET, SOCK_STREAM, 0);
  if (sockToServer < 0) {
    perror("error creating socket");
    exit(1);
  }
  struct hostent *server = gethostbyname(serverName.c_str());
  if (server == NULL) {
    fprintf(stderr,"ERROR, no such host\n");
    exit(1);
  }
  struct sockaddr_in serverAddr;
  memset(&serverAddr, sizeof(serverAddr), 0);
  serverAddr.sin_family = AF_INET;
  memcpy((char*)&serverAddr.sin_addr.s_addr, (char*)server->h_addr, server->h_length);
  serverAddr.sin_port = htons(portNum);
  cout << "trying to connect to server" << endl;
  if (connect(sockToServer, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) < 0) {
    perror("cannot connect");
    exit(1);
  }
  int ret = write(sockToServer, password, 8);
  if (ret < 0) {
    perror("ERROR writing to socket");
    exit(1);
  }
  cout << "connected to server" << endl;
}


int main(int argc, char *argv[]) {
  assert(argc >= 3);
  int queueNum = atoi(argv[1]);
  cout << "using queue num " << queueNum << endl;
 
  if (strcmp(argv[2], "log") == 0) {
    if (argc >= 4) {
      delay = atof(argv[3]);
    }
    cout << "delaying " << delay << " seconds" << endl;
    activateNFQ(queueNum, &cb);
  } else if (strcmp(argv[2], "inject") == 0) {
    assert(argc >= 7);
    numClients = atoi(argv[3]);
    cout << "number of clients: " << numClients << endl;
    delay = atof(argv[4]);
    cout << "delaying somewhere around " << delay << " seconds" << endl;
    variation = atof(argv[5]);
    cout << "variation " << variation << " seconds" << endl;
    throttle = atof(argv[6]);
    cout << "throttle " << throttle << " seconds" << endl;
    setupSockToClient();
    cout << "creating new sendPacket thread" << endl;
    thread sendThread(sendPackets);
    activateNFQ(queueNum, cbAddToWaiting);
  } else if (strcmp(argv[2], "detect") == 0) {
    string serverName = "socialr.xyz";
    setupSockToServer(serverName);
    cout << "creating new detectPacket thread" << endl;
    thread detectThread(detectPackets);
    activateNFQ(queueNum, cbDetect);
  }
  cout << "final return" << endl;
  return 0;
}
