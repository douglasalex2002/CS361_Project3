#include <arpa/inet.h>
#include <assert.h>
#include <check.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/dhcp.h"

START_TEST (C_test_template)
{
  int x = 5;
  int y = 5;
  ck_assert_int_eq (x, y);
}
END_TEST

START_TEST (test_append_cookie)
{
  uint8_t *packet = malloc(10);
  size_t size = 10;
  
  packet = append_cookie(packet, &size);
  
  ck_assert_int_eq(size, 14);
  free(packet);
}
END_TEST

START_TEST (test_append_option)
{
  uint8_t *packet = malloc(10);
  size_t size = 10;
  uint8_t value = 5;
  
  packet = append_option(packet, &size, DHCP_opt_msgtype, 1, &value);
  
  ck_assert_int_eq(size, 13); // 10 plus code plus len plus value
  free(packet);
}
END_TEST

void public_tests (Suite *s)
{
  TCase *tc_public = tcase_create ("Public");
  tcase_add_test (tc_public, C_test_template);
  tcase_add_test (tc_public, test_append_cookie);
  tcase_add_test (tc_public, test_append_option);
  suite_add_tcase (s, tc_public);
}

