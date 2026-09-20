/*
 * End-to-end fixture for trexida.
 *
 * Built with no debug information so that IDA sees no types at all; TRex must reconstruct:
 *   - `node`   : { 4-byte int at offset 0, self-referential pointer at offset 8 }  (linked list)
 *   - `pair`   : struct with members at offsets 0 / 8 / 12, accessed with a constant stride
 *   - `get_last`'s parameter : pointer to `node`
 */
#include <stdint.h>

struct node
{
  int32_t value;
  struct node *next;
};

struct pair
{
  uint64_t a;
  uint32_t b;
  uint32_t c;
};

__declspec(noinline) struct node *get_last(struct node *head)
{
  struct node *cur = head;
  while (cur != 0 && cur->next != 0)
    cur = cur->next;
  return cur;
}

__declspec(noinline) uint32_t sum_pairs(struct pair *p, int n)
{
  uint32_t sum = 0;
  for (int i = 0; i < n; ++i)
  {
    sum += (uint32_t)p[i].a;
    sum += p[i].b;
    sum += p[i].c;
  }
  return sum;
}

__declspec(noinline) int32_t union_read(void *p, int which)
{
  if (which == 0)
    return (int32_t)*(int32_t *)p;
  if (which == 1)
    return (int32_t)*(int16_t *)p;
  return (int32_t)*(int8_t *)p;
}

int main(int argc, char **argv)
{
  struct node n2 = {2, 0};
  struct node n1 = {1, &n2};
  struct pair ps[2] = {{1, 2, 3}, {4, 5, 6}};
  struct node *last = get_last(&n1);
  return (int)(last->value + sum_pairs(ps, 2) + union_read(argv, argc));
}
