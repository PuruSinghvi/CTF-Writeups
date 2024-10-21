## Guessy Programmer 0
### Description
Adventurer beware!
This challenge is not for the faint of heart.
Scour through the text. Find its innate meaning.
Find the red flags.
Find what you search for.

**PS**
Regular expressions are the weapon of a true programmer. Not as clumsy or random as a search engine; an elegant tool from a more civilized age.

- `([Oo][Bb][Ii])-+([Ww][Aa][Nn]) ?(K[Ee][Nn][Oo][Bb][iI])+`
### Files
[guessy_programmer_0](./guessy_programmer_0)

## Writeup
We have a git bundle file, we can use `git clone` to form a repository.
```bash
git clone guessy_programmer_0 repo_0
```
>Cloning into 'repo_0'...
>Receiving objects: 100% (1578/1578), 273.61 KiB | 4.64 MiB/s, done.

In this repo we see a file named `adventure_novel.txt` which has many fake flags, with the wrong format. We know the correct flag will have sun along with two curly braces and anything in between. So we can use simple regex to search for it:  `sun\{.*?\}`
`sun{w@it_w@s_1t_th@t_e@sy_r3g3x_is_n0t_@_f@ir_@dventure_here_take_this_sun_flag{_secret_flag}`