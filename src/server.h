#ifndef __cs361_dhcp_server_h__
#define __cs361_dhcp_server_h__

#include <stdbool.h>
#include <stdint.h>

#include "dhcp.h"

int setup_server (char *, long to_seconds);

extern bool debug;
extern struct in_addr THIS_SERVER;

#endif
