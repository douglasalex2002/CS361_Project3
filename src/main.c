#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "dhcp.h"
#include "format.h"
#include "port_utils.h"
#include "server.h"

static bool get_args (int, char **, long *);

bool debug = false;

int
main (int argc, char **argv)
{
  long to_seconds = 2;
  bool success = get_args (argc, argv, &to_seconds);
  if (!success)
    return EXIT_FAILURE;

  char *protocol = get_port ();
  int socketfd = setup_server (protocol, to_seconds);
  if (socketfd < 0)
    return EXIT_FAILURE;

  // Indicate (for debugging) that the server is running
  fprintf (stderr, "Server is started on port %s\n", protocol);

  if (debug)
    fprintf (stderr, "Shutting down\n");
  return EXIT_SUCCESS;
}

static bool
get_args (int argc, char **argv, long *to_seconds)
{
  int ch = 0;
  while ((ch = getopt (argc, argv, "dhs:t:")) != -1)
    {
      switch (ch)
        {
        case 'd':
          debug = true;
          break;
        case 's':
          *to_seconds = atol(optarg);
          break;
        case 't':
          // lets just ignore this for now, due it at later phase
          break;
        default:
          return false;
        }
    }
  return true;
}
