#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include "dhcp.h"
#include "format.h"

const char* print_hardware_type(uint8_t htype) {
  switch(htype) {
    case ETH: return "Ethernet (10Mb)";
    case IEEE802: return "IEEE 802 Networks";
    default: return "Unknown";
  }
}

const char* print_message_type(uint8_t type) {
  switch(type) {
    case DHCPDISCOVER: return "DHCP Discover";
    case DHCPOFFER: return "DHCP Offer";
    case DHCPREQUEST: return "DHCP Request";
    case DHCPACK: return "DHCP ACK";
    default: return "Unknown";
  }
}

void
dump_msg (FILE *output, msg_t *msg, size_t size)
{
  fprintf (output, "------------------------------------------------------\n");
  fprintf (output, "BOOTP Options\n");
  fprintf (output, "------------------------------------------------------\n");
  
  if (msg->op == BOOTREQUEST) {
    fprintf(output, "Op Code (op) = %d [BOOTREQUEST]\n", msg->op);
  } else if (msg->op == BOOTREPLY) {
    fprintf(output, "Op Code (op) = %d [BOOTREPLY]\n", msg->op);
  }
  
  fprintf(output, "Hardware Type (htype) = %d [%s]\n", msg->htype, print_hardware_type(msg->htype));
  fprintf(output, "Hardware Address Length (hlen) = %d\n", msg->hlen);
  fprintf(output, "Hops (hops) = %d\n", msg->hops);
  
  fprintf(output, "Transaction ID (xid) = %u (0x%x)\n", ntohl(msg->xid), ntohl(msg->xid)); // both formats
  
  uint16_t seconds = ntohs(msg->secs);
  int days = seconds / 86400;
  int hours = (seconds % 86400) / 3600;
  int minutes = (seconds % 3600) / 60;
  int secs = seconds % 60;
  fprintf(output, "Seconds (secs) = %d Days, %d:%02d:%02d\n", days, hours, minutes, secs);
  
  fprintf(output, "Flags (flags) = %d\n", ntohs(msg->flags));
  
  char ipstr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &msg->ciaddr, ipstr, INET_ADDRSTRLEN);
  fprintf(output, "Client IP Address (ciaddr) = %s\n", ipstr);
  
  inet_ntop(AF_INET, &msg->yiaddr, ipstr, INET_ADDRSTRLEN);
  fprintf(output, "Your IP Address (yiaddr) = %s\n", ipstr);
  
  inet_ntop(AF_INET, &msg->siaddr, ipstr, INET_ADDRSTRLEN);
  fprintf(output, "Server IP Address (siaddr) = %s\n", ipstr);
  
  inet_ntop(AF_INET, &msg->giaddr, ipstr, INET_ADDRSTRLEN);
  fprintf(output, "Relay IP Address (giaddr) = %s\n", ipstr);
  
  // only hlen bytes
  fprintf(output, "Client Ethernet Address (chaddr) = ");
  for (int i = 0; i < msg->hlen; i++) {
    fprintf(output, "%02x", msg->chaddr[i]);
  }
  fprintf(output, "\n");
  
  fprintf (output, "------------------------------------------------------\n");
  fprintf (output, "DHCP Options\n");
  fprintf (output, "------------------------------------------------------\n");
  
  // remember to parse
  uint8_t *option_start = (uint8_t*)msg + sizeof(msg_t);
  uint8_t *option_end = (uint8_t*)msg + size - 1;
  
  options_t options;
  memset(&options, 0, sizeof(options_t));
  
  bool result = get_options(option_start, option_end, &options);
  // printf("get_options returned %d\n", result);
  
  if (result) {
    fprintf(output, "Magic Cookie = [OK]\n");
    
    if (options.type != NULL) {
      fprintf(output, "Message Type = %s\n", print_message_type(*options.type));
    }
    
    if (options.request != NULL) {
      inet_ntop(AF_INET, options.request, ipstr, INET_ADDRSTRLEN);
      fprintf(output, "Request = %s\n", ipstr);
    }
    
    if (options.lease != NULL) {
      uint32_t lease_time = ntohl(*options.lease);
      int lease_days = lease_time / 86400;
      int lease_hours = (lease_time % 86400) / 3600;
      int lease_mins = (lease_time % 3600) / 60;
      int lease_secs = lease_time % 60;
      fprintf(output, "IP Address Lease Time = %d Days, %d:%02d:%02d\n", lease_days, lease_hours, lease_mins, lease_secs);
    }
    
    if (options.sid != NULL) {
      inet_ntop(AF_INET, options.sid, ipstr, INET_ADDRSTRLEN);
      fprintf(output, "Server Identifier = %s\n", ipstr);
    }
    
    free_options(&options);
  }
}
