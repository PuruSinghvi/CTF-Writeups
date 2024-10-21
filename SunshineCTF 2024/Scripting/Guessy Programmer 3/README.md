## Guessy Programmer 3
### Description
Adventurer beware!
This challenge is not for the faint of heart.
ł ₴ɆɆ ₮₩Ø ₮Ɏ₱Ɇ₴ Ø₣ ₱ɆØ₱ⱠɆ: ₮ⱧØ₴Ɇ ₩ⱧØ ₳ⱤɆ ₩łⱠⱠł₦₲ ₮Ø ₴Ɇ₳Ɽ₵Ⱨ ฿ł₦₳ⱤłɆ₴... ₳₦Đ ₮ⱧØ₴Ɇ ₩ⱧØ ₳ⱤɆ ₦Ø₮.
G̴̵͈̥̣͉ͩ̌̓̽ͦ̕͡o̷̢̗̗͙̦̼̞̳̝͖̼̘͙͎̝̹̍ͭ̂͊͒͗̀͊͛̐̈̊͋͒̅̓͊̍̌ͣͥ͛̕͟͝͠o̷̵͖͍͓͙͇̣͇̻̟̜ͬͮ͋ͧͦͦ̋͋̒̀̏͆̈̿ͭ̈́͑̚͡d̵ͥͩ ĺ̟̖͎͔̜̙͚͉͍̰̤ͥ̊͒ͧ̊ͩ͂͌̾͒͌̽̓̐ͪ̆̔̊̎̓ͤ͊ͩ̔͘͞ͅu̶̜̘̠̐͑ͩ̄͌ͩ͌̉͋͜͞c̴̴̶̴͔̲͚̬̦̳͇͈̹̀̇̇̀̈́̄̾̍̉̔́̒̌͆̐̽̍ͣ͟k̯̻̉̓ͪ̀͜ t̴̬͍̯̹̪̳ͫ͐͛ͩ̉ͥ͒̉͗̚͘͟_̆̈́ͫŕ̸̸̷̲͍̞̹̠̰̰͈̭̦̹͍͇̒̃͊̈́̾̏̈́ͮ̒̑͗ͤ̆̄͂̀̆͌͑̾́̚͟͢͜͟͡͡͝ȧv̸͓ͬ͒ͤ̕͜͜_̼̮͍̟̘̝ͫͩ̔̀̅̊̓ͪ̎̏̀e̵̟̥͍͎͈̠̊ͭ͑̒̐̑͒̔͂ͪͪ͞l̵̪̞̥̘̩͓̻͙̺̮ͮ͒ͤͣ͗ͩ̉ͣͩ͐̏̽ͭ͆ͫ͢͢͞ȩ͇̤̭̖̈̿͋̓ͮͥŗ̛̠̲̣̭̝̯̜̙͎̻̲̯̒̿͑̋͋ͣ̾́̈̉̓͆͢͜.̷̨̢͇̟͔̫͈͇͙̐͆̿ͬ̄̃ͭͦ̀̅̑̃̃̍̈̐͟͞ͅͅͅͅ
𝐌⃥⃒̸𝐚⃥⃒̸𝐲⃥⃒̸ 𝐰⃥⃒̸𝐞⃥⃒̸ 𝐦⃥⃒̸𝐞⃥⃒̸𝐞⃥⃒̸𝐭⃥⃒̸ 𝐚⃥⃒̸𝐠⃥⃒̸𝐚⃥⃒̸𝐢⃥⃒̸𝐧⃥⃒̸,⃥⃒̸ 𝐨⃥⃒̸𝐧⃥⃒̸ 𝐦⃥⃒̸𝐨⃥⃒̸𝐫⃥⃒̸𝐞⃥⃒̸ 𝐝⃥⃒̸𝐞⃥⃒̸𝐜⃥⃒̸𝐞⃥⃒̸𝐧⃥⃒̸𝐭⃥⃒̸ 𝐭⃥⃒̸𝐞⃥⃒̸𝐫⃥⃒̸𝐦⃥⃒̸𝐬⃥⃒̸.⃥⃒̸
**PS**
Only persons ignorant of regexes (regexi?) deal in absolutes.
Which come to think of it is an absolute statement.
Well... you can kill my regexes (regexi?), but you will never destroy them! They will always be legacy code!

- `(([Oo][Bb][Ii])-+([Ww][Aa][Nn]) ?(K[Ee][Nn][Oo][Bb][iI])+)????`
### Files
[guessy_programmer_3](./guessy_programmer_3)

## Writeup
We have a git bundle file, we can use `git clone` to form a repository.
```bash
git clone guessy_programmer_3 repo_3
```
>Cloning into 'repo_3'...
>Receiving objects: 100% (1882/1882), 335.72 KiB | 6.33 MiB/s, done.
>Resolving deltas: 100% (620/620), done.

In this repo, there is a .gitattributes file, which gives us an idea of what the challenge is about, and also has a fake flag:
```
# git keeps trying to add .gif files as text! idk why, it's like it sees them as text.
## anyway nice catch, here's a flag:
## sun{nice_flag_nice_catch_o_wait_this_is_not_a_valid_flag_huh_must_be_in_the_gifs_after_all]
*.gif binary
```

However, there doesn't seem to be any other file. Since there is a .git folder, there must be previous commits' data we can view.

First let's see what all files were deleted:
```bash
git log --diff-filter=D --name-only --pretty=format:
```
>adventure_novel_3.gif

So only adventure_novel_3.gif was ever deleted. Let's try to extract all the commits/changes made to this file:
```bash
git log --patch --follow -- adventure_novel_3.gif > full_history.txt
```
Unfortunately this doesn't work. This is because git treats .gif file as binaries, and therefore don't show the actual difference between commits. It only shows that the files were changed, with the keyword `diff`:
`Binary files a/adventure_novel_3.gif and b/adventure_novel_3.gif differ`

To bypass this, we can use this `--text` attribute:
```bash
git log --patch --follow --text -- adventure_novel_3.gif > ful
l_history.txt
```

Again we run a regex to look for sun{}: `sun\{.*?\}`, we didn't find anything. This means the correct flag is encoded with base64.

I loaded the file full_history.txt in cyberchef, applied the base64 decode recipe, and again searched with the regex. But again I got nothing.
However, knowing how base64 decoding works, the problem could be that the correct string is not being decoded properly. So, I started removing initial characters from this input, and testing the search for every char removed. After removing the first three, `com`, the search worked, and I got the flag:
`sun{u_realize_you_could_have_converted_the_gitattributes_to_be_text_with_a_refactor_and_then_just_solve_it_as_normal_oh_well_strings_also_works}`