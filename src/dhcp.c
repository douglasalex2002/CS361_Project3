#include <arpa/inet.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dhcp.h"

void
dump_packet (uint8_t *ptr, size_t size)
{
  size_t index = 0;
  while (index < size)
    {
      fprintf (stderr, " %02" PRIx8, ptr[index++]);
      if (index % 32 == 0)
        fprintf (stderr, "\n");
      else if (index % 16 == 0)
        fprintf (stderr, "  ");
      else if (index % 8 == 0)
        fprintf (stderr, " .");
    }
  if (index % 32 != 0)
    fprintf (stderr, "\n");
  fprintf (stderr, "\n");
}

void
free_options (options_t *options)
{
  if (options->request != NULL)
    {
      free (options->request);
      options->request = NULL;
    }
  if (options->lease != NULL)
    {
      free (options->lease);
      options->lease = NULL;
    }
  if (options->type != NULL)
    {
      free (options->type);
      options->type = NULL;
    }
  if (options->sid != NULL)
    {
      free (options->sid);
      options->sid = NULL;
    }
}

bool
get_options (uint8_t *packet, uint8_t *end, options_t *options)
{
  // check magic cookie
  uint32_t cookie;
  memcpy (&cookie, packet, 4);
  if (ntohl (cookie) != MAGIC_COOKIE)
    {
      // fprintf(stderr, "bad cookie: %x\n", ntohl(cookie));
      return false;
    }

  // we want to skip past the cookie
  uint8_t *current = packet + 4;

  while (current <= end)
    {
      uint8_t option_type = *current;

      if (option_type == DHCP_opt_end)
        {
          break;
        }

      current++;
      if (current > end)
        break;

      uint8_t option_len = *current;
      current++;

      if (current + option_len > end + 1)
        break;

      if (option_type == DHCP_opt_msgtype)
        {
          options->type = malloc (1);
          *options->type = *current;
        }
      else if (option_type == DHCP_opt_reqip)
        {
          options->request = malloc (sizeof (struct in_addr));
          memcpy (options->request, current, 4);
        }
      else if (option_type == DHCP_opt_lease)
        {
          options->lease = malloc (4);
          memcpy (options->lease, current, 4);
        }
      else if (option_type == DHCP_opt_sid)
        {
          options->sid = malloc (sizeof (struct in_addr));
          memcpy (options->sid, current, 4);
        }
      /* printf("parsed option %d, length %d\n", option_type, option_len); */

      current += option_len;
    }

  return true;
}

uint8_t *
append_cookie (uint8_t *packet, size_t *packet_size)
{
  size_t newsize = *packet_size + 4;
  uint8_t *newpacket = realloc (packet, newsize);

  uint32_t cookie = htonl (MAGIC_COOKIE);
  memcpy (newpacket + *packet_size, &cookie, 4);

  *packet_size = newsize;
  return newpacket;
}

uint8_t *
append_option (uint8_t *packet, size_t *packet_size, uint8_t option,
               uint8_t option_size, uint8_t *option_value)
{
  if (option == DHCP_opt_end)
    {
      size_t newsize = *packet_size + 1;
      uint8_t *newpacket = realloc (packet, newsize);
      newpacket[*packet_size] = DHCP_opt_end;
      *packet_size = newsize;
      return newpacket;
    }

  // code plus length than value
  size_t newsize = *packet_size + 2 + option_size;
  uint8_t *newpacket = realloc (packet, newsize);

  uint8_t *position = newpacket + *packet_size;
  *position = option;
  position++;
  *position = option_size;
  position++;
  memcpy (position, option_value, option_size);

  *packet_size = newsize;
  return newpacket;
}
