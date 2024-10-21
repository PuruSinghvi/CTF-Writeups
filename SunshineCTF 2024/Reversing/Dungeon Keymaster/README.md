## Dungeon Keymaster
### Description
The sun blazes down upon the CTF. Just as though it were a summer day in florida.

In the dungeon, though, another adventure awaits for CTF-ers. This dungeon has no light, such that the staring sun cannot stare into its depths. In this dungeon, the keymaster awaits. Tell the master the code, and he will free thee, and will show the sunlight to the wary traveler.

https://keymaster.2024.sunshinectf.games/

## Writeup
The start of this reversing challenge was interesting, because we weren't given the binary directly.
Opening https://keymaster.2024.sunshinectf.games/ I played with it a bit. From the error message we get the key format:
`Invalid key format. It must be in the format: string-string-string.`

and analyzing the source, we see this:
```html
<html>
<head>
	<title>Dungeon Challenge</title>
</head>
<style>
body {
  background-image: url('https://s3.amazonaws.com/dungeon-keymaster.2024.sunshinectf.games/dungeon_entrance.jpg');
}
h1,p,form,label {
	background-color: white
}
</style>
<body>
	<h1>Welcome to the Dungeon Challenge!</h1>
	<p>Only those with the correct key may enter and retrieve the treasure.</p>
	<form action="/" method="POST">
		<label for="key">Enter your key:</label><br>
		<input type="text" id="key" name="key" required><br><br>
		<input type="submit" value="Submit Key">
	</form>
	
</body>
</html>
```
From here we got the amazon bucket link: https://s3.amazonaws.com/dungeon-keymaster.2024.sunshinectf.games
When this is opened we get a list of all the accessible resources.
The binary we have to reverse was in `.build/app`, therefore https://s3.amazonaws.com/dungeon-keymaster.2024.sunshinectf.games/.build/app

I used IDA to decompile this binary, it is Go binary so any other decompiler won't do a very good job, since only IDA can read and assign the function names.
We know that this is a form which is run from the binary directly. The function `main_handleForm` is the one which handles the form. But this is not the function we are interested in. `main_handleForm` calls a function, after taking the input, which is `main_checkKey`.

```c
// main.checkKey
_BOOL8 __golang main_checkKey(__int64 a1, __int64 a2)
{
  __int64 v2; // rdx
  __int64 v3; // r14
  void *v4; // rbx
  __int64 v5; // rax
  char v7[40]; // [rsp+58h] [rbp-28h] BYREF
  void *retaddr; // [rsp+80h] [rbp+0h] BYREF
  __int64 v9; // [rsp+88h] [rbp+8h]
  __int64 v10; // [rsp+88h] [rbp+8h]

  while ( (unsigned __int64)&retaddr <= *(_QWORD *)(v3 + 16) )
  {
    v10 = a1;
    runtime_morestack_noctxt();
    a1 = v10;
  }
  v9 = a1;
  strings_genSplit(1LL, 0LL, v2, &unk_7AC959, -1LL);
  if ( a2 != 3 )
    return 0LL;
  v4 = off_A82830;
  v5 = runtime_concatstring5(
         v7,
         off_A82830,
         qword_A82838,
         &unk_7AC959,
         1LL,
         off_A82840,
         qword_A82848,
         &unk_7AC959,
         1LL,
         off_A82850,
         qword_A82858);
  return v4 == &unk_3 && (unsigned __int8)runtime_memequal(v9, v5);
}
```

This function mostly had inbuilt Golang functions.
`runtime_morestack_noctxt` is used to increase memory space if the program is running out of it.

`strings_genSplit` seems to be splitting a string, into multiple parts, with a delimiter stored in `unk_7AC959`. This delimiter is hyphen:
`unk_7AC959      db  2Dh ; -`
which makes complete sense.

```c
 if ( a2 != 3 )
    return 0LL;
```
This is probably the number of strings we get after splitting the input, which should be exactly three, since the key has the format `string-string-string`.

```c
v5 = runtime_concatstring5(
         v7,
         off_A82830,
         qword_A82838,
         &unk_7AC959,
         1LL,
         off_A82840,
         qword_A82848,
         &unk_7AC959,
         1LL,
         off_A82850,
         qword_A82858);
  return v4 == &unk_3 && (unsigned __int8)runtime_memequal(v9, v5);
```
`runtime_concatstring5` is also a Go function, which simply concats 5 different strings into one, and stores the output in v5.
In the end, `runtime_memequal` compares v9 (input) and v5 (output of runtime_concatstring5) to check if they are exactly equal. This is the main check we have to pass, so to find the key we simply have to calculate v5! (not that easy).

Analyzing the parameters passed into it, let's see `off_A82830`. This points to a very large string constant.
```c
const char aFlagsLenDConnV[4244] =
" flags= len=%d (conn) %v=%v,expiresrefererrefreshtrailerGODEBUG:method:scheme:statushttp://chunkednosniffCreatedIM Usedwriteat19531259765625invaliduintptrSwapperChanDir using , type= Value>Convert{{end}} actioncommandoperandAvestanBengaliBrailleCypriotDeseretElbasanElymaicGranthaHanunooKannadaMakasarMandaicMarchenMultaniMyanmarOsmanyaSharadaShavianSiddhamSinhalaSogdianSoyomboTagalogTibetanTirhutaAacute;Ab............................. {very long}
```
This is how strings are stored in Go binaries, they are all combined into one, and it is very difficult to find which one is used where.

Then `qword_A82838    dq 8`. This stores the decimal value 8. It means that the first part of the string has a length of 8.

`unk_7AC959      db  2Dh ; -` This stores the hyphen, which is what comes after the first word. The `1LL` after this signifies the length of this hyphen, which is 1 char.

Next looking at `off_A82840`:
```c
off_A82840      dq offset unk_7ACD0E
.rodata:00000000007ACD0E unk_7ACD0E      db  38h ; 8             ; DATA XREF: .data:off_A82840↓o
.rodata:00000000007ACD0F                 db  37h ; 7
.rodata:00000000007ACD10                 db  33h ; 3
.rodata:00000000007ACD11                 db  34h ; 4
```
and `qword_A82848    dq 4`

This means the 2nd word is a 4 letter word, and is simply `8734`.
Once again we have the `unk_7AC959` (hyphen) and `1LL` combination.

`off_A82850      dq offset aMissingValueFo+640h`
This is another big string like the first one.
```c
const char aMissingValueFo[10747] =
"missing value for %sEgyptian_HieroglyphsMeroitic_HieroglyphsDoubleLongLeftArrow;DownLeftRightVector;LeftArrowRightArrow;NegativeMediumSpace;RightArrowLeftArrow;SquareSupersetEqual;leftrightsquigarrow;NotGreaterFullEqual;NotRightTriangleBar;if/with can't use %vnil is not a commanderror calling %s: %windex of untyped nilindex of nil pointerslice of untyped niljson: error calling unknown PSK identitycertificate requiredtime: invalid number/usr/share/zonein............................. {very long}
```

`qword_A82858    dq 21`
This means the length of the third word should be 21 chars.

So to proceed after this, for a long time I bruteforced various combinations of `{8_letter_word}-8734-{21_letter_word}`. I took multiple "interesting" strings from both the set of large strings, which I thought could be the keyword, then tried all combinations possible.
After long hours of failing, I finally decided to switch to dynamic analysis, which gave the flag really fast.

I proceeded with the Remote Linux Debugger of IDA, by connecting it with wsl.
Here is a very helpful article if you want to setup something similar: https://eviatargerzi.medium.com/remote-debugging-with-ida-from-windows-to-linux-4a98d7095215

I setup multiple breakpoints in the `main_checkKey` function, right after the `runtime_concatstring5` function is called:
<p align='center'>
  <img src='/images/sunshineidadebubrek.jpg'>
</p>

When the binary is run, it starts a local server similar to the form we saw earlier:
`Server started at http://localhost:8734`
Going to http://localhost:8734/ and entering any key like a-b-c when we press Submit Key, we hit a breakpoint.
<p align='center'>
  <img src='/images/sunshinerevhit1.jpg'>
</p>

But we won't get the concatenated string from this, so we press the play button to move ahead, which takes us to the next breakpoint:
<p align='center'>
  <img src='/images/sunshinebreahit2.jpg'>
</p>

The formed flag is stored starting from the RAX register, so clicking on the arrow, we can see the value stored inside it:
```c
debug003:000000C00001C1B0 db  2Fh ; /
debug003:000000C00001C1B1 db  64h ; d
debug003:000000C00001C1B2 db  75h ; u
debug003:000000C00001C1B3 db  6Eh ; n
debug003:000000C00001C1B4 db  67h ; g
debug003:000000C00001C1B5 db  65h ; e
debug003:000000C00001C1B6 db  6Fh ; o
debug003:000000C00001C1B7 db  6Eh ; n
debug003:000000C00001C1B8 db  2Dh ; -
debug003:000000C00001C1B9 db  38h ; 8
debug003:000000C00001C1BA db  37h ; 7
debug003:000000C00001C1BB db  33h ; 3
debug003:000000C00001C1BC db  34h ; 4
debug003:000000C00001C1BD db  2Dh ; -
debug003:000000C00001C1BE db  68h ; h
debug003:000000C00001C1BF db  74h ; t
debug003:000000C00001C1C0 db  74h ; t
debug003:000000C00001C1C1 db  70h ; p
debug003:000000C00001C1C2 db  3Ah ; :
debug003:000000C00001C1C3 db  2Fh ; /
debug003:000000C00001C1C4 db  2Fh ; /
debug003:000000C00001C1C5 db  6Ch ; l
debug003:000000C00001C1C6 db  6Fh ; o
debug003:000000C00001C1C7 db  63h ; c
debug003:000000C00001C1C8 db  61h ; a
debug003:000000C00001C1C9 db  6Ch ; l
debug003:000000C00001C1CA db  68h ; h
debug003:000000C00001C1CB db  6Fh ; o
debug003:000000C00001C1CC db  73h ; s
debug003:000000C00001C1CD db  74h ; t
debug003:000000C00001C1CE db  3Ah ; :
debug003:000000C00001C1CF db  38h ; 8
debug003:000000C00001C1D0 db  37h ; 7
debug003:000000C00001C1D1 db  33h ; 3
debug003:000000C00001C1D2 db  34h ; 4
```
Using this, we form the key, which is `/dungeon-8734-http://localhost:8734`
Very weird looking key by the way, this was intentionally made so that we cannot bruteforce "possible" keys from the large strings we have in Go binaries!

When we input this key in the original website, we get a reply:
`Correct key! You may enter the dungeon at /dungeon.`
But upon accessing /dungeon https://keymaster.2024.sunshinectf.games/dungeon
we still get 
```
# Access Denied!
Invalid key format.
```

I think we have to go through the binary and try to understand the valid format to submit key in /dungeon. But I just guessed it on my first try, by sending it as ?key=
And so, accessing the link as https://keymaster.2024.sunshinectf.games/dungeon?key=/dungeon-8734-http://localhost:8734
gives us the flag!
`sun{behold_challenger_here_is_the_answer_to_thy_wishes_three_here_is_the_contents_of_the_dungeon_key}`
