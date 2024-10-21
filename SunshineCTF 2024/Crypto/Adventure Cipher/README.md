## Adventure Cipher

### Description
Can you crack Sir Alaric's message?

Note: The alphabet is `abcdefghijklmnopqrstuvwxyz_<space>{}` (where `<space>` is " ")
## Files
[server.pem](./letter.txt)

## Writeup
The description gives us a 30 character alphabet, and the letter.txt has random words, but exactly 30 unique words.
This is enough to infer that every word corresponds to a character, and we have to find the correct mapping to get the flag.

At first I mapped the words according to the order in which they appear.
```python
alphabet = 'abcdefghijklmnopqrstuvwxyz_ {}'
words = [
    "Escapade", "Wander", "Ridge", "Passage", "Travel", "Pilgrimage", "Venture", 
    "Quest", "Trek", "Wanderlust", "Journey", "Adventure", "Pathway", "Voyage", 
    "Exploration", "Trail", "Migration", "Expedition", "Pursuit", "Traverse", 
    "Sojourn", "Crossing", "Odyssey", "Field", "Discovery", "Survivor", "Roaming", 
    "River", "Bridge", "Valley"
]
word_to_letter = {word: alphabet[i] for i, word in enumerate(words)}

data = """ {contents of letter.txt} """

def replace_words_with_letters(data, word_to_letter):
    words_in_data = data.split()
    result = []
    
    for word in words_in_data:
        result.append(word_to_letter.get(word, word))
    
    return ''.join(result)

output = replace_words_with_letters(data, word_to_letter)
print(output)
```

This gave us a very interesting string `alf{nidjklae{ninmjr{noh{winzf}`
I could infer from this that we have mapped `}` correctly, but rest is unclear.

To further analyze this, I looked at the count of each word:
```js
{'Escapade': 329, 'Wander': 198, 'Ridge': 701, 'Passage': 69, 'Travel': 51, 'Pilgrimage': 421, 'Venture': 230, 'Quest': 146, 'Trek': 150, 'Wanderlust': 231, 'Journey': 72, 'Adventure': 199, 'Pathway': 190, 'Voyage': 295, 'Exploration': 224, 'Trail': 74, 'Migration': 109, 'Expedition': 82, 'Pursuit': 78, 'Traverse': 53, 'Sojourn': 4, 'Crossing': 21, 'Odyssey': 69, 'Field': 33, 'Discovery': 2, 'Survivor': 11, 'Roaming': 6, 'River': 1, 'Bridge': 4, 'Valley': 1}
```

In the end you can see that `River` and `Valley` appears exactly once, therefore, they must be `{` and `}` respectively (order based on their occurrence).
`Bridge` appears exactly 4 times so it must be `_`

Changing the mapping accordingly and rerunning the script gives us another peculiar string:
`injdfhcalfcgqo{alf_nidjklae_ninmjr_noh_winzf}cnohcwf`
We can see the flag is inside curly braces, and since flag format is `sun{}`, the three letters before the curly braces, `gqo` must be swapped with `sun`.

We can also guess that the char right before the flag, that is `c`, should be a space, since the flag won't have any other char before its format.

Now, before getting to this point, I manually guessed a lot of words to try to make some sense. Like I replaced the mapping of  `gqo` with `sun`, then formed two words in the flag, `the` and `and`.
But all this was not required, since simply after mapping the correct word for `<space>` we can use an online tool for further analysis.

So after mapping space correctly, with the word `Ridge`, this is what I used in the original script:
```python
words = [
    "Escapade", "Wander", "Roaming", "Passage", "Travel", "Pilgrimage", "Venture", 
    "Quest", "Trek", "Wanderlust", "Journey", "Adventure", "Pathway", "Voyage", 
    "Exploration", "Trail", "Migration", "Expedition", "Pursuit", "Traverse", 
    "Sojourn", "Crossing", "Odyssey", "Field", "Discovery", "Survivor", "Bridge", 
    "Ridge", "River", "Valley"
]
```

Then I analyzed the output using this tool https://www.dcode.fr/monoalphabetic-substitution
which correctly calculated the substitution cipher keys and also the flag:
`sun{the_almighty_alaric_and_blaqe}`
