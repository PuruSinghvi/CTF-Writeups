## Melbourne
### Description
Drive on down the I-95 to your favorite cities along the way! First up: Melbourne!
`nc 2024.sunshinectf.games 24601`
### Files
[melbourne](./melbourne)

## Writeup
Very basic pwn challenge, I decompiled the binary using IDA.
The program appears to check user input and, if a certain condition is met, prints out the contents of "flag.txt."
The string `s1` is not initialized or populated in the code. This hints at a vulnerability where the comparison relies on unintended values in `s1`.

Since `fgets(s, 140, stdin);` reads up to 140 bytes from standard input, but the buffer `s` only has 112 bytes, there is a potential for buffer overflow.
The overflow could overwrite the contents of `s1` with controlled input, including `"0xdeadbeef"`, which could allow us to pass the check.

We need to input 112 characters (to fill `s`), followed by `"0xdeadbeef"` to overwrite `s1`

```python
payload = "A" * 112 + "0xdeadbeef"
```

>Flag is: `sun{Windows are quite enjoyable to look out of. I think there's a duck over there.}`