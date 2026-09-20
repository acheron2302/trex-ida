// Fixture for tests/e2e/test_interproc.py: inter-procedural type propagation across call sites.
//
// The three callees are exported so IDA names them (an export table carries names but no types),
// which lets the test pick their rows out of .trex.vars.tsv by name.
//
// `pass` is an identity function: its parameter and its returned value must end up with the same
// type. It is called twice, with a `struct A *` and a `struct B *`; `A` and `B` disagree about what
// lives at offset 0 (an `int` versus a `double`), so a caller that only knows "some pointer" gets a
// union of the two once inter-procedural propagation is on, and two unrelated types when it is off.

struct A { int x; int y; };    // fields at offsets 0 and 4
struct B { double p; int q; }; // field at offset 0 conflicts with A's

__declspec(dllexport) void *pass(void *v) { return v; }
__declspec(dllexport) int use_a(struct A *a) { return a->x + a->y; }
__declspec(dllexport) int use_b(struct B *b) { return (int)b->p + b->q; }

int main(void)
{
  struct A a = { 1, 2 };
  struct B b = { 3.0, 4 };
  int r = use_a((struct A *)pass(&a));
  r += use_b((struct B *)pass(&b));
  return r;
}
