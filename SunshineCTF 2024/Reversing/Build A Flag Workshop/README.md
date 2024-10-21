## Build A Flag Workshop
### Description
Don't you ever want to customize your very own flag? Well now you can with Chompy's brand new Build-A-Flag-Workshop (patent pending)!
### Files
[build-a-flag-workshop](./build-a-flag-workshop)

## Writeup
First I tried to run the binary:
```
|-----------------------------------|
| Welcome to Build-A-Flag Workshop! |
|-----------------------------------|
| Your flag: live_long_prosper
|
| 1: Length    [0]
| 2: Genre     [0]
| 3: Vibe      [0]
| 4: Signature []
|
| [NA]: Chompy's flag check
|
| x: Exit
```

It forms a flag, by combining two strings. The first string is a random string, selected using the combination of Length, Genre and Vibe which we select. This first string is then connected with a our "Signature" (which can be anything we type) through a hyphen `-`.

Now I decompiled this binary in IDA. There were multiple function to handle the flag building part, but one function was peculiar:
```c
void __fastcall sub_19C0(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        __int128 a7,
        __int128 a8,
        __int128 a9,
        __int128 a10,
        __int128 a11,
        __int128 a12,
        __int128 a13)
{
  __m128i v13; // xmm0
  char *v14; // rax
  char *v15; // rbx
  char *v16; // r13
  char *v17; // rbp
  char *v18; // r12
  size_t v19; // rax
  int v20; // eax
  const char *v21; // rcx
  __m128i v22; // [rsp+10h] [rbp-A8h]
  __m128i v23; // [rsp+20h] [rbp-98h]
  __m128i v24; // [rsp+30h] [rbp-88h]
  __int128 v25; // [rsp+70h] [rbp-48h] BYREF
  unsigned __int64 v26; // [rsp+88h] [rbp-30h]

  v13 = _mm_loadu_si128((const __m128i *)&a7);
  v26 = __readfsqword(0x28u);
  v22 = _mm_loadu_si128((const __m128i *)&a8);
  v23 = _mm_loadu_si128((const __m128i *)&a9);
  v24 = _mm_loadu_si128((const __m128i *)&a10);
  v14 = (char *)sub_1370(
                  a1,
                  a2,
                  a3,
                  a4,
                  a5,
                  a6,
                  v13.m128i_i64[0],
                  v13.m128i_i64[1],
                  v22.m128i_i64[0],
                  v22.m128i_i64[1],
                  v23.m128i_i64[0],
                  v23.m128i_i64[1],
                  v24.m128i_i64[0],
                  v24.m128i_i64[1]);
  if ( v14 )
  {
    v15 = v14;
    v16 = strtok(v14, "-");
    v17 = strtok(0LL, "-");
    v18 = strtok(0LL, "-");
    if ( v16 )
    {
      puts(v16);
      if ( v17 )
      {
        puts(v17);
        if ( v18 )
          puts(v18);
        if ( strstr(v16, "decide") )
        {
          v19 = strlen(v17);
          MD5(v17, v19, &v25);
          if ( xmmword_4010 == v25 )
          {
            if ( v18 )
            {
              v20 = strcmp(v18, "chompy");
              v21 = "is Chompy's favorite flag! Great work.";
              if ( !v20 )
                goto LABEL_15;
            }
          }
        }
        goto LABEL_14;
      }
    }
    else if ( v17 )
    {
      puts(v17);
      if ( !v18 )
      {
LABEL_14:
        v21 = "isn't Chompy's favorite, but it's yours and that's what matters.";
LABEL_15:
        __printf_chk(2LL, "sun{%s} %s\n", v15, v21);
        free(v15);
        return;
      }
LABEL_13:
      puts(v18);
      goto LABEL_14;
    }
    if ( !v18 )
      goto LABEL_14;
    goto LABEL_13;
  }
  puts("Failed to generate flag.");
}
```

Analyzing this function, we know that some sort of input or something is first divided into three parts, using the delimiter hyphen `-`.

- It checks if the *first part* contains the substring `decide`.
- The MD5 sum of *second part* is calculated, and compared to `xmmword_4010`.
- The *third part* is directly compared with `chompy`.

If the string satisfies all three conditions, it is wrapped in sun{} and is declared as Chompy's favorite flag. It is pretty clear from here what our main goal is, it is to find Chompy's favourite flag!

#### Part 1
The first part should have `decide` as a substring, but that could mean any string. However, if we look into the flag building workshop, that is the original way of flag forming, we find multiple strings, which are chosen randomly based on some conditions of Length, Genre and Vibe.

We can get all of them directly using the `strings` command:
```
not_all_those_who_wander_are_lost
what_we_do_in_life_echoes_in_eternity
infinite_diversity_infinite_combinations
the_force_will_be_with_you_always
ive_seen_things_you_people_wouldnt_believe
all_we_have_to_decide_is_what_to_do_with_the_time_given_to_us
the_only_thing_we_have_to_fear_is_fear_itself
live_long_prosper
resistance_is_futile
hasta_la_vista_baby
you_shall_not_pass
chaos_is_a_ladder
i_feel_the_need_for_speed
i_think_therefore_i_am
soylent_green_is_people
humanity_is_cancer
one_does_not_simply
winter_is_coming
what_is_dead_may_never_die
heres_looking_at_you_kid
veni_vidi_vici
fear_is_the_mind_killer
dont_panic
second_breakfast
dark_and_full_of_terrors
im_gonna_make_him_an_offer
madness_is_like_gravity
```

Only one of these contains the keyword `decide`, i.e. `all_we_have_to_decide_is_what_to_do_with_the_time_given_to_us` which makes this the first part of our flag.

#### Part 2
We have the find the string whose MD5 hash is same as `xmmword_4010`   
When I first looked into this data, I was very confused.

`xmmword_4010    xmmword 71D9DEF108882B6AAF6AE378098517ABh`
Though this displays a string of the exact length of a MD5 hash, `71D9DEF108882B6AAF6AE378098517AB` is not a hash, but merely a hexadecimal representation of the data stored which makes up the hash.

I decided to use Ghidra to decompile this binary, to better look at the data.
Ghidra also shows the same function with slightly different code:
```c
MD5(d,n,(uchar *)&local_48);
if (((local_48 ^ _DAT_00104010 | local_40 ^ _DAT_00104018) != 0) || (__s_00 == (char *)0))
```

```c
                             DAT_00104010                                    XREF[1]:     FUN_001019c0:00101aeb (R)   
        00104010 ab              ??         ABh
        00104011 17              ??         17h
        00104012 85              ??         85h
        00104013 09              ??         09h
        00104014 78              ??         78h    x
        00104015 e3              ??         E3h
        00104016 6a              ??         6Ah    j
        00104017 af              ??         AFh
                             DAT_00104018                                    XREF[1]:     FUN_001019c0:00101af2 (R)   
        00104018 6a              ??         6Ah    j
        00104019 2b              ??         2Bh    +
        0010401a 88              ??         88h
        0010401b 08              ??         08h
        0010401c f1              ??         F1h
        0010401d de              ??         DEh
        0010401e d9              ??         D9h
        0010401f 71              ??         71h    q
```

The hash value is divided into two different data variables and stored. We can simply read and combine them to form the correct hash: `AB17850978E36AAF6A2B8808F1DED971`.
I cracked this hash using CrackStation https://crackstation.net/

| Hash                             | Type | Result  |
| -------------------------------- | ---- | ------- |
| AB17850978E36AAF6A2B8808F1DED971 | md5  | gandalf |
Therefore, the second part of the flag is `gandalf`.

#### Part 3
We know the third part is directly compared to `chompy`, therefore this is the third part of our flag.

Combining these parts, we get our flag: `sun{all_we_have_to_decide_is_what_to_do_with_the_time_given_to_us-gandalf-chompy}`