#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "dhcp.h"
#include "format.h"
#include "port_utils.h"
#include "server.h"

#define MAX_IPS 5

int
setup_server (char *protocol __attribute__ ((unused)), long to_seconds __attribute__ ((unused)))
{
  return 0;
}
