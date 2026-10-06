/* Own inert PE32 fixture: no entry point, no imports, no shield/client code. */
__attribute__((section(".cowpg"), aligned(4096)))
volatile unsigned char cow_page[4096] = {0x31,0x57,0x9b,0xdf};
