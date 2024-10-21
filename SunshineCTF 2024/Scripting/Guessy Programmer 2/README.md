## Guessy Programmer 2
### Description
Adventurer beware!
This challenge is not for the faint of heart.
Scour through history, through time, through place.
Wait it's not working this time.
No fair, this is a scripting challenge? How is making this be forensics fair?
Wait you say forensics is part of adventures? How? Why?
Automated forensics???
WHY HAVE YOU DONE THIS TO ME???

**PS**
It's over, Anakin. I have the high regex.

- `([Oo][Bb][Ii])-+([Ww][Aa][Nn]) ?(K[Ee][Nn][Oo][Bb][iI])+==`
### Files
[guessy_programmer_2](./guessy_programmer_2)

## Writeup
We have a git bundle file, we can use `git clone` to form a repository.
```bash
git clone guessy_programmer_2 repo_2
```
>Cloning into 'repo_2'...
>Receiving objects: 100% (1881/1881), 341.98 KiB | 6.84 MiB/s, done.

In this repo we see a file named `adventure_novel_2.txt` but it is empty. But since there is a .git folder, there must be data in this file, still stored in previous commits!

We can get the full commit history, including all changes made to any file (additions and removals) using this command:
```bash
git log --patch --follow -- adventure_novel_2.txt > full_history.txt
```

Now when we run a regex to look for sun{}: `sun\{.*?\}`, we didn't find anything. This means the correct flag is encoded with base64.

I loaded the file full_history.txt in cyberchef, applied the base64 decode recipe, and again searched with the regex. But again I got nothing.
However, knowing how base64 decoding works, the problem could be that the correct string is not being decoded properly. So, I started removing initial characters from this input, and testing the search for every char removed. After removing the first two, `co`, the search worked, and I got the flag:
`sun{base64_is_no_fair_that_requires_me_to_work_dude}`