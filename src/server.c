#include <arpa/inet.h>
#include <getopt.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h> 
#include <netinet/in.h>

#include "dhcp.h"
#include "format.h"
#include "port_utils.h"
#include "server.h"

#define MAX_IPS 5
#define MAX_CLIENTS 4
#define CHADDR_LEN 16

struct in_addr THIS_SERVER;

struct lease 
{
  bool used; 
  uint8_t chaddr[CHADDR_LEN];
  struct in_addr ip;
};

static struct lease leases[MAX_CLIENTS];

static void
init_leases (void)
{
  for (int i = 0; i < MAX_CLIENTS; i++)
    {
      leases[i].used = false; 
    }
}

static bool
same_chaddr (const uint8_t *a, const uint8_t *b)
{
  for (int i = 0; i < CHADDR_LEN; i++)
    {
      if (a[i] != b[i]) return false;
    }
  
  return true; 
}

static struct lease *
find_lease (const uint8_t *chaddr)
{
  for (int i = 0; i < MAX_CLIENTS; i++)
    {
      if (leases[i].used && same_chaddr(leases[i].chaddr, chaddr))
        {
          return &leases[i];
        }
    }
  
    return NULL; 
}

static struct in_addr
ip_for_index (int idx)
{
  struct in_addr addr;
  uint32_t base = (192U << 24) | (168U << 16) | (1U << 8) | 1U;
  uint32_t ip = htonl (base + (uint32_t)idx);
  addr.s_addr = ip;
  return addr; 
}

static struct lease *
assign_lease (const uint8_t *chaddr)
{
  struct lease *existing = find_lease (chaddr);
  if (existing != NULL)
    {
      return existing;
    }
  
    for (int i = 0; i < MAX_CLIENTS; i++)
      {
        if(!leases[i].used)
          {
            leases[i].used = true;
            memcpy (leases[i].chaddr, chaddr, CHADDR_LEN);
            leases[i].ip = ip_for_index (i);
            return &leases[i];
          }
      }

    return NULL; 
}

int
setup_server (char *protocol, long to_seconds)
{
  inet_pton(AF_INET, "192.168.1.0", &THIS_SERVER);
  
  // UDP socket
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return -1;
  }
  
  // timeout set here 
  struct timeval timeout;
  timeout.tv_sec = to_seconds;
  timeout.tv_usec = 0;
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    perror("setsockopt");
    close(sock);
    return -1;
  }
  
  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(atoi(protocol));
  
  if (bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
    perror("bind");
    close(sock);
    return -1;
  }

  // initialize leases for phase 2
  init_leases();
  
  uint8_t buf[MAX_DHCP_LENGTH];
  struct sockaddr_in client_addr;
  socklen_t addrlen = sizeof(client_addr);
  
  while (1) {
    memset(buf, 0, MAX_DHCP_LENGTH);
    
    // getting the message from client
    int bytes = recvfrom(sock, buf, MAX_DHCP_LENGTH, 0, 
                          (struct sockaddr*)&client_addr, &addrlen);
    // printf("received %d bytes\n", bytes);
    
    if (bytes < 0) {
      if (debug) {
        fprintf(stderr, "Receive timeout\n");
    }
      break;
    }
    
    fprintf(stdout, "++++++++++++++++++++++++++\n");
    fprintf(stdout, "SERVER RECEIVED %d BYTES:\n", bytes);
    fprintf(stdout, "++++++++++++++++++++++++++\n\n");
    
    msg_t *msg = (msg_t*)buf;
    
    dump_msg(stdout, msg, bytes);
    fprintf(stdout, "\n");
    
    uint8_t *options_start = buf + sizeof(msg_t);
    uint8_t *options_end = buf + bytes - 1;
    
    options_t options;
    memset(&options, 0, sizeof(options_t));
    get_options(options_start, options_end, &options);
    
    uint8_t message_type = 0;
    if (options.type != NULL) {
      message_type = *options.type;
    }
    // fprintf(stderr, "message type is %d\n", message_type);

    // Phase 1: XID == 0
    if (msg -> xid == 0)
      {
        msg_t reply;
        memset(&reply, 0, sizeof(msg_t));
        
        reply.op = BOOTREPLY;
        reply.htype = msg->htype;
        reply.hlen = msg->hlen;
        reply.hops = 0;
        reply.xid = msg->xid;
        reply.secs = 0;
        reply.flags = 0;
        
        memcpy(reply.chaddr, msg->chaddr, 16);
        
        inet_pton(AF_INET, "192.168.1.1", &reply.yiaddr);
        
        // building the response packet
        uint8_t *response = malloc(sizeof(msg_t));
        memcpy(response, &reply, sizeof(msg_t));
        size_t response_size = sizeof(msg_t);
        
        // next add magic cookie
        response = append_cookie(response, &response_size);
        // printf("after cookie size = %ld\n", response_size);
        
        uint8_t reply_type;
        if (message_type == DHCPDISCOVER) {
          reply_type = DHCPOFFER;
        } else if (message_type == DHCPREQUEST) {
          reply_type = DHCPACK;
        } else {
          reply_type = DHCPNAK;
        }
        response = append_option(response, &response_size, DHCP_opt_msgtype, 1, &reply_type);
        
        if (reply_type != DHCPNAK)
          {
            uint32_t lease_time = htonl(30 * 24 * 60 * 60); // 30 days
            response = append_option(response, &response_size, DHCP_opt_lease, 4, (uint8_t*)&lease_time);
          }

        response = append_option(response, &response_size, DHCP_opt_sid, 4, (uint8_t*)&THIS_SERVER);
        
        uint8_t end = DHCP_opt_end;
        response = append_option(response, &response_size, DHCP_opt_end, 0, &end);
        
        fprintf(stdout, "+++++++++++++++++++++++++\n");
        fprintf(stdout, "SERVER SENDING %ld BYTES:\n", response_size);
        fprintf(stdout, "+++++++++++++++++++++++++\n\n");
        
        dump_msg(stdout, (msg_t*)response, response_size);
        
        sendto(sock, response, response_size, 0, 
              (struct sockaddr*)&client_addr, addrlen);
        
        free(response);
        free_options(&options);
        
        // TODO later
        break;
      }

else  // Phase 2: XID != 0
      {
        msg_t reply;
        memset(&reply, 0, sizeof(msg_t));

        reply.op   = BOOTREPLY;
        reply.htype = msg->htype;
        reply.hlen  = msg->hlen;
        reply.hops  = 0;
        reply.xid   = msg->xid;
        reply.secs  = 0;
        reply.flags = 0;

        memcpy(reply.chaddr, msg->chaddr, 16);

        uint8_t reply_type = DHCPNAK;   // default
        struct lease *lease = NULL;

        if (message_type == DHCPDISCOVER)
          {
            // reuse or assign a lease
            lease = assign_lease(msg->chaddr);

            if (lease == NULL)
              {
                // 5th distinct client → NAK, yiaddr stays 0.0.0.0
                if (debug)
                  fprintf(stderr, "No free leases; sending NAK\n");
                reply_type = DHCPNAK;
              }
            else
              {
                reply.yiaddr = lease->ip;
                reply_type = DHCPOFFER;
              }
          }
        else if (message_type == DHCPREQUEST)
          {
            struct in_addr req_server_id;
            struct in_addr req_ip;
            bool have_sid   = false;
            bool have_reqip = false;
          
            if (options.sid != NULL)
              {
                req_server_id = *options.sid;
                have_sid = true;
              }

            if (options.request != NULL)
              {
                req_ip = *options.request;
                have_reqip = true;
              }
          
            lease = find_lease(msg->chaddr);

            bool ok = true;

            if (!have_sid || !have_reqip)
              ok = false;
            else if (req_server_id.s_addr != THIS_SERVER.s_addr)
              ok = false;
            else if (lease == NULL)
              ok = false;
            else if (req_ip.s_addr != lease->ip.s_addr)
              ok = false;
          
            if (ok)
              {
                reply.yiaddr = lease->ip;
                reply_type = DHCPACK;
              }
            else
              {
                // mismatch somewhere → NAK, yiaddr remains 0.0.0.0
                reply_type = DHCPNAK;
              }
          }
        else
          {
            // unknown/unsupported type; leave reply_type = NAK
            if (debug)
              fprintf(stderr, "Unknown DHCP message type %u\n", message_type);
          }

        // ----- Build and send Phase 2 response -----
        uint8_t *response = malloc(sizeof(msg_t));
        memcpy(response, &reply, sizeof(msg_t));
        size_t response_size = sizeof(msg_t);

        response = append_cookie(response, &response_size);

        response = append_option(response, &response_size,
                                 DHCP_opt_msgtype, 1, &reply_type);
        
        if (reply_type != DHCPNAK)
          {
          uint32_t lease_time = htonl(30 * 24 * 60 * 60); // 30 days
          response = append_option(response, &response_size,
                                  DHCP_opt_lease, 4, (uint8_t*)&lease_time);
          }
        response = append_option(response, &response_size,
                                 DHCP_opt_sid, 4, (uint8_t*)&THIS_SERVER);

        uint8_t end = DHCP_opt_end;
        response = append_option(response, &response_size,
                                 DHCP_opt_end, 0, &end);

        fprintf(stdout, "+++++++++++++++++++++++++\n");
        fprintf(stdout, "SERVER SENDING %ld BYTES:\n", response_size);
        fprintf(stdout, "+++++++++++++++++++++++++\n\n");

        dump_msg(stdout, (msg_t*)response, response_size);

        sendto(sock, response, response_size, 0,
               (struct sockaddr*)&client_addr, addrlen);

        free(response);
        free_options(&options);
        // NOTE: no break; Phase 2 keeps serving until timeout
      }
    }  
  close(sock);
  return sock;
}
