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

using uint64 = uint64_t;
using int64 = int64_t;
using uint32 = uint32_t;

const int64 million = 1000000;
const double millionDouble = 1000000.0;
const int64 billion = 1000000000;

int64 period = 0; // in microseconds
double fastSpeed = 0.0; // in packets/second
double slowSpeed = 0.0; // in packets/second
int numClients = 0;

const int minPacketLength = 1000;

struct Client {
  int sock;
  socklen_t clientLen;
  struct sockaddr_in addr;
  string username;
};
vector<Client> clients;
  


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
  return chrono::time_point_cast<chrono::duration<int64, micro>>(
            chrono::system_clock::now()).time_since_epoch().count();
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
  int64 delay = 0;
  req.tv_sec = floor(delay);
  req.tv_nsec = floor((delay - floor(delay))*billion);

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
  const int64 halfPeriod = period/2; //in microsends
  enum SPEED {
    FAST,
    SLOW
  };
  SPEED speed = FAST;

  vector<SentPacket> sentPackets; // waiting to send to client(s)
  int64 firstAdded = getTime(); // for knowing how long to wait to send to client(s)

  const int bucketSize = 3; // a parameter for smoothing out the fast speed
  queue<int64> sentTimes; // the last bucketSize sent times
  while (sentTimes.size() < bucketSize) {
    sentTimes.push(0);
  }

  int64 startTime = getTime();

  while (true) {
    assert(sentTimes.size() == bucketSize);
    int64 now = getTime();
    if ((now - startTime) % period < halfPeriod) {
      speed = FAST;
    } else {
      speed = SLOW;
    }

    int64 targetTime;
    if (speed == FAST) {
      targetTime = sentTimes.front() + bucketSize*(int64)(million/fastSpeed);
    } else {
      targetTime = sentTimes.back() + million/slowSpeed;
    }

    unique_lock<mutex> lock(waitingPacketsMutex);
    while (waitingPackets.empty()) {
      waitingPacketsCv.wait(lock);
    } 
    now = getTime();
    int64 toWait = targetTime - now; 
    if (speed == SLOW && (now % period) + toWait >= period) {
      toWait = min(toWait, 
                   max(period - (now % period),
                       sentTimes.front() + bucketSize*(int64)(million/fastSpeed)));
    }
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
    cout << "sent packet with size " << toSend.length << endl;
    assert(ret >= 0);
    sentTimes.push(time);
    sentTimes.pop();

    now = getTime();
    if ((now - startTime) % period < halfPeriod) {
      speed = FAST;
    } else {
      speed = SLOW;
    }

    sentPackets.push_back(SentPacket(toSend.length, toSend.createdTime, time));
    if ((sentPackets.size() >= 10 || (sentPackets.size() >= 2 && time - firstAdded >= 2*million)) &&
        speed == SLOW) {
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


double stdDev(const vector<int>& vec) {
  assert(vec.size() > 1);
  double total = 0.0;
  for (int x : vec) {
    total += x;
  }
  double average = total / vec.size();
  
  double sumDiffSq = 0.0;
  for (int x : vec) {
    const double diff = x - average;
    sumDiffSq += diff*diff;
  }

  double variance = sumDiffSq/(vec.size() - 1);
  return sqrt(variance);
}


void runDetection(const vector<ArrivedPacket>& seenPackets, bool lastRun) {
  const int trials = 20; // the amount of different offsets to try
  const int64 halfPeriod = period / 2;

  // The number to find in a half period to count the download as started
  const int globSize = 10; 
  const int endGlobSize = 3; // to have ended
  int begin; // the beginning index of the download, inclusive
  for (begin = 0; begin + globSize - 1 < seenPackets.size(); ++begin) {
    if (seenPackets[begin + globSize - 1].arrivedTime - 
        seenPackets[begin].arrivedTime < halfPeriod) {
      break;
    }
  }
  if (begin + globSize - 1 >= seenPackets.size()) {
    if (lastRun) {
      cerr << "didn't detect start of download" << endl;
      exit(1);
    } else {
      cout << "didn't detect start of download yet" << endl;
      return;
    }
  }

  int end; // exclusive
  if (lastRun) {
    for (end = seenPackets.size(); end - endGlobSize >= begin; --end) {
      if (seenPackets[end - 1].arrivedTime - 
          seenPackets[end - endGlobSize].arrivedTime < halfPeriod) {
        break;
      }
    }
  } else {
    end = seenPackets.size();
  }
  if (end <= begin || end <= 0 || end > seenPackets.size()) {
    if (lastRun) {
      cerr << "could not find end of download" << endl;
      exit(1);
    } else {
      cout << "couldn't get range yet" << endl;
      return;
    }
  }

  cout << "There are " << end - begin << " valid seen packets in range" << endl;
  cout << "they span " << (seenPackets[end-1].arrivedTime - 
                           seenPackets[begin].arrivedTime)/millionDouble
       << " seconds" << endl;

  int bestTrial = 0;
  double bestDifference = 0.0;
  double bestHighAverage = 0.0;
  double bestLowAverage = 0.0;
  vector<int> bestHighCounts; // full half periods
  vector<int> bestLowCounts; // full half periods

  const int64 beginTime = seenPackets[begin].arrivedTime;
  for (int i = 0; i < trials; ++i) {
    int64 offset = (i*halfPeriod)/trials;
    int aPackets = 0;
    int bPackets = 0;

    // full periods, used for computed the best*counts vectors
    const int numPeriods = (seenPackets[end-1].arrivedTime - 
                            (seenPackets[begin].arrivedTime + offset))/period;
    vector<int> aCounts(numPeriods, 0);
    vector<int> bCounts(numPeriods, 0);
    int64 aTime = numPeriods * halfPeriod;
    int64 bTime = numPeriods * halfPeriod;


    for (int j = begin; j < end; ++j) {
      if (seenPackets[j].arrivedTime < beginTime + offset) {
        continue; // skip the offset
      }
      const int periodNum = (seenPackets[j].arrivedTime - (beginTime + offset))/period;
      const int periodOffset = (seenPackets[j].arrivedTime - (beginTime + offset)) % period;
      if (periodNum < numPeriods) {
        if (periodOffset < halfPeriod) {
          ++aCounts[periodNum];
        } else {
          ++bCounts[periodNum];
        }
      }
      if (periodOffset < halfPeriod) {
        ++aPackets;
      } else {
        ++bPackets;
      }
    }

    const int64 leftoverTime = seenPackets[end-1].arrivedTime - 
                               (beginTime + offset) - numPeriods*period;
    assert(leftoverTime >= 0);
    assert(leftoverTime < period);
    aTime += min(leftoverTime, halfPeriod);
    bTime += max((int64)0, leftoverTime - halfPeriod);

    double aAverage, bAverage;
    if (leftoverTime < halfPeriod) {
      aAverage = ((double)aPackets - 0.5)/(aTime/millionDouble);
      bAverage = ((double)bPackets)/(bTime/millionDouble);
    } else {
      aAverage = ((double)aPackets)/(aTime/millionDouble);
      bAverage = ((double)bPackets - 0.5)/(bTime/millionDouble);
    }
    
    double highAverage, lowAverage;
    vector<int> highCounts, lowCounts;
    if (aAverage >= bAverage) {
      highAverage = aAverage;
      lowAverage = bAverage;
      highCounts = aCounts;
      lowCounts = bCounts;
    } else {
      highAverage = bAverage;
      lowAverage = aAverage;
      highCounts = bCounts;
      lowCounts = aCounts;
    }

    const double difference = highAverage - lowAverage;
    if (difference > bestDifference) {
      bestDifference = difference;
      bestTrial = i;
      bestHighAverage = highAverage;
      bestLowAverage = lowAverage;
      bestHighCounts = highCounts;
      bestLowCounts = lowCounts;
    }
  }

  double bestHighStdDev = stdDev(bestHighCounts);
  double bestLowStdDev = stdDev(bestLowCounts);

  cout << "bestTrial: " << bestTrial << " bestDifference: " << bestDifference << endl;
  cout << "bestHighAverage: " << bestHighAverage << " bestLowAverage: " << bestLowAverage << endl;
  cout << "bestHighStdDev: " << bestHighStdDev << "bestLowStdDev: " << bestLowStdDev << endl;
  return;
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
      if (arrivedPackets.front().length >= minPacketLength) {
        seenPackets.push_back(arrivedPackets.front());
      }
      arrivedPackets.pop();
      cout << "new packet seen " << seenPackets.back().length << endl;
    }
    arrivedPacketsMutex.unlock();

    ofstream ofsSeen("seenpackets.csv", ios_base::app);
    for (int i = seenWritten; i < seenPackets.size(); ++i) {
      ofsSeen << seenPackets[i].id << ',' << seenPackets[i].length << ','
              << seenPackets[i].arrivedTime << '\n';
      ++seenWritten;
    }
    ofsSeen.close();

    ofstream ofsSent("sentpackets.csv", ios_base::app);
    for (int i = sentWritten; i < sentPackets.size(); ++i) {
      ofsSent << sentPackets[i].length << ',' << sentPackets[i].sentTime << '\n';
      ++sentWritten;
    }
    ofsSent.close();

    cout << "There are " << seenPackets.size() << " ok seen packets" << endl;

    runDetection(seenPackets, false);

    if (seenPackets.size() > 600 && seenPackets.back().arrivedTime - getTime() >= 5*million) {
      cout << "saw " << seenPackets.size() << " packets and it has been "
           << seenPackets.back().arrivedTime - getTime()
           << " seconds since last packet so stopping collection" << endl;
      break;
    }
    this_thread::sleep_for(chrono::milliseconds(2000));
  }
  runDetection(seenPackets, true);
  cout << "all done with detection" << endl;
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
    if (ret != 8) {
      perror("error getting password");
      exit(1);
    }
    buffer[7]= '\0';
    if (strcmp(buffer, password) != 0) {
      cerr << "wrong password, got " << buffer << endl;
      close(client.sock);
    } else {
      ret = write(client.sock, &period, sizeof(period));
      if (ret != sizeof(period)) {
        perror("could not send period to client");
        exit(1);
      }
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
  if (ret != 8) {
    perror("ERROR writing to socket");
    exit(1);
  }
  ret = read(sockToServer, &period, sizeof(period));
  if (ret != sizeof(period)) {
    perror("error getting the period");
    exit(1);
  }
  cout << "got period " << period << endl;
  cout << "connected to server" << endl;
}


int main(int argc, char *argv[]) {
  assert(argc >= 3);
  int queueNum = atoi(argv[1]);
  cout << "using queue num " << queueNum << endl;
 
  if (strcmp(argv[2], "log") == 0) {
    activateNFQ(queueNum, &cb);
  } else if (strcmp(argv[2], "inject") == 0) {
    assert(argc == 7);
    numClients = atoi(argv[3]);
    cout << "number of clients: " << numClients << endl;
    double periodDouble = atof(argv[4]);
    cout << "fluctuation period is " << periodDouble << " seconds " << endl;
    period = periodDouble * million;
    slowSpeed = atof(argv[5]);
    cout << "slow speed is " << slowSpeed << " packets/sec" << endl;
    fastSpeed = atof(argv[6]);
    cout << "fast speed is <= " << fastSpeed << " packets/sec" << endl;
    setupSockToClient();
    cout << "creating new sendPacket thread" << endl;
    thread sendThread(sendPackets);
    activateNFQ(queueNum, cbAddToWaiting);
  } else if (strcmp(argv[2], "detect") == 0) {
    assert(argc == 3);
    string serverName = "socialr.xyz";
    setupSockToServer(serverName);
    cout << "creating new detectPacket thread" << endl;
    thread detectThread(detectPackets);
    activateNFQ(queueNum, cbDetect);
  }
  cout << "final return" << endl;
  return 0;
}
