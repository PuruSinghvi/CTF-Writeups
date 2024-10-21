## Twine
### Description
You'd think with a name like "Twine" I'd at least do something with threads!

Note: Flag format: `flag{}`
### Files
[challenge](./challenge)

## Writeup
We have a linux binary:
challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=65e6dfbcc1da958f798b3425c2562aed9c6ae9c4, for GNU/Linux 4.4.0, not stripped

When decompiled using IDA, we see a function named flag(), which has the correct flag :)
```c
const char *flag()
{
  return "flag{youd_be_better_off_reading_the_source_code_directly_but_i_guess_this_is_fine}";
}
```

