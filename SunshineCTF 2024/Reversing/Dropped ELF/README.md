## Dropped ELF
### Description
Oh no! I dropped my ELF and now it's shattered to pieces :( How will I ever get the flag now??
### Files
[dropped.zip](./dropped.zip)

## Writeup
The dropped zip has 11 files, named from 0 to 10, each one a piece to one ELF.
First thing I did is ran file command on every file, which gave me an interesting answer for piece 2:
>2: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), can't read elf program headers at 736, missing section headers at 75672

This definitely means that the this is the starting part of the binary. Our goal is to find the correct order of these parts, then merge them to get the flag.

Usually I use https://hexed.it/ to analyze files, but it was mistakenly closing files due to the hitbox being very close. So for this challenge I used https://hex-works.com/ instead.

Analyzing all the parts I made some observations:
`2` is the starting.
`3` and `5` are mostly empty, so placing them anywhere is difficult.
`7` contains the strings used inside the binary.
`1`, `8`, `10` has random data, but all three has similar patterns, so they might be somewhere close.

I tried to see if any parts got connected by having similar starting-ending, but didn't find any such pattern.
It was clear that even if we manage to get some parts right, we will have to do some bruteforcing for the remaining parts. 10! = 3628800 so we can't just bruteforce all of them!

I solved this challenge by comparing these parts, to a full binary from the `Twine` reversing challenge, as they both seem to have similar sizes.

A short while after the ELF headers, I noticed a string `/lib64/ld-linux-x86-64.so.2` in the full binary.
Part `4` has an exact string, so I can assume that the order is `2->4`

Once again right after this, I get another interesting string in the full binary `puts __libc_start_main __cxa_finalize libc.so.6 GLIBC_2.2.5 GLIBC_2.34 _ITM_deregisterTMCloneTable __gmon_start__ _ITM_registerTMCloneTable`
and surprisingly part `0` had an extremely similar string `__cxa_finalize __libc_start_main printf libc.so.6 GLIBC_2.2.5 GLIBC_2.34 _ITM_deregisterTMCloneTable __gmon_start__ _ITM_registerTMCloneTable`

This confirmed for me that the first three parts are `2->4->0`.

Analyzing the full binary, we can see that the ending is very unique. A short while before the end, there is are many strings, which from my guess are the function names. The last one is `.data .bss .comment` which is exactly same in the part `6`.
This confirms that part `6` is the last part.

Now right before these large number of strings, we get some information about the compiler `GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4`, which luckily for us is already included in part `6`. The interesting thing however, is that right before the compiler information, there is some gibberish data, and right before that the strings used in the binary are listed.
This corresponds to part `7` which has `The flag is: sun{%x}` string followed by the gibberish data.

So we have confirmed that the order is:
`2`
`4`
`0`
{`1`,`3`,`5`,`8`,`9`,`10`}
`7`
`6`

I spent some time trying to make sense of the remaining parts, but after my failures, it turned out that it is not even required. We are left with 6 parts with no place, i.e. 6! = 720 possibilities, which can be easily bruteforced!

So I wrote this script, it tries all the permutations of the remaining parts, joins them to form a binary, gives the binary permission to be executed, tries to execute it, and captures the error/output, and saves everything in a text file!
```python
import itertools
import os
import subprocess

elf_parts = ["2", "4", "0", "1", "3", "5", "8", "9", "10", "7", "6"]
middle_parts = elf_parts[3:9]
output_file = "elf_output_log.txt"

with open(output_file, "w") as f:
    f.write("ELF reconstruction log\n")

def merge_parts(order, output_file_name):
    with open(output_file_name, "wb") as outfile:
        for part in order:
            with open(part, "rb") as infile:
                outfile.write(infile.read())

# Try all permutations of the middle parts
for perm in itertools.permutations(middle_parts):
    full_order = elf_parts[:3] + list(perm) + elf_parts[9:]
    merged_elf = "reconstructed_elf"
    merge_parts(full_order, merged_elf)

    os.chmod(merged_elf, 0o755)

    try:
        result = subprocess.run(f"./{merged_elf}", capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired as e:
        output = f"Error: Execution timeout\n{str(e)}"
    except Exception as e:
        output = f"Error: {str(e)}"

    with open(output_file, "a") as f:
        f.write(f"\nAttempt with order: {full_order}\n")
        f.write(output)
```

Opening the text file, we first got to see errors like `unsupported version 14801 of Verneed record` or `unsupported version 30081 of Verneed record`
but searching for `sun{` takes us right to the correct output.
```
Attempt with order: ['2', '4', '0', '9', '3', '5', '10', '1', '8', '7', '6']
The flag is: sun{58b2f9c5}
```

Therefore, the correct order is `2->4->0->9->3->5->10->1->8->7->6`!
and the flag is `sun{58b2f9c5}`


