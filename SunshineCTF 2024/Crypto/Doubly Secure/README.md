## Doubly Secure
**Note: Special thanks to my teammate [Maximxls](https://github.com/maximxlss) who did most of the work for this challenge!**
### Description
Shh. This website only has TLS enabled. Come here and we can talk more privately.

## Writeup
We have the website https://secure.2024.sunshinectf.games/ which when opened presents us with this:
```
# Shhhh

        age1ffjry4a30x2vj9g50ayhvq0wzgkny6k0q3ce88swj86ru8zth9ms0927fc
    

[We can talk here](https://secure.2024.sunshinectf.games/ws)
```

Looking at this text `age1ffjry4a30x2vj9g50ayhvq0wzgkny6k0q3ce88swj86ru8zth9ms0927fc`, we see that it starts with `age1`, this means that it is a public key of age encryption system.
https://github.com/FiloSottile/age

The link https://secure.2024.sunshinectf.games/ws when opened in browser simply gives `Bad Request`, but we can guess that ws probably stands for `websocket`, so we have to deal with this using a different tool: [websocat](https://github.com/vi/websocat/releases/download/v1.13.0/websocat.x86_64-unknown-linux-musl)

```bash
./websocat wss://secure.2024.sunshinectf.games/ws
```
> websocat: WebSocketError: WebSocket SSL error: error:0A000086:SSL routines:tls_post_process_server_certificate:certificate verify failed:ssl/statem/statem_clnt.c:2091: (unable to get local issuer certificate)
> websocat: error running

Okay, so we need to run this without requiring any verification. We can use the `--insecure` tag:
```bash
./websocat --insecure wss://secure.2024.sunshinectf.games/ws
```
>input
>don't recognize that message
>hello
>don't recognize that message

The server responds with `don't recognize that message` for any input we send.

From here we need to analyze all the clues, "We can talk here", "we can talk more **privately**".
And all that we have is a public key, which is used to encrypt data. Therefore it is evident that we have to send data by encrypting it with the public key first!
(again thanks to Maxim for figuring this out!)

Let's try to encrypt a command and then send it to the server:
```bash
echo ls | age -r age1ffjry4a30x2vj9g50ayhvq0wzgkny6k0q3ce88swj86ru8zth9ms0927fc > enc
```
We need to use `-b` to send data:
```bash
cat enc | ./websocat -b --insecure wss://secure.2024.sunshinectf.game
s/ws
```
> what kind of key is this?

The response is very interesting, it seems like the person behind the chat wants a key. Since we want to have a "private" chat, it seems he wants our public key, so that he can then send data (or maybe flag?) by encrypting with it, and no one can read it!

I used this online tool to generate keys, and do the encryption/decryption: https://age-wasm.ey.r.appspot.com/

Generated public and private key respectively:
`age1dyfd4w0x30494unpadj43wu44ajcuxwgcxwz6vqnflaw8paqr3vss59spa`
`AGE-SECRET-KEY-1RJ5KQAZWLZRFAH62Y4MRV48ZL2H7LQ298V6PJ05UW9ZL56JVTGSSSWTA3L`

Encrypted my public key with the public key given on the website:
```bash
echo age1dyfd4w0x30494unpadj43wu44ajcuxwgcxwz6vqnflaw8paqr3vss59spa |
 age -r age1ffjry4a30x2vj9g50ayhvq0wzgkny6k0q3ce88swj86ru8zth9ms0927fc > enckey
```

Then sent the encrypted file:
```bash
cat enckey | ./websocat -b --insecure wss://secure.2024.sunshinectf.g
ames/ws
```
>YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSB5L083Q082SDN3Mi9ZaTRFV01tOWlqYnNQaDlwdTlDaFdXSUtIemJSb2xjCjd2Y2NOT3V3MGdzLzZIcWZ2bUthMndUUHZqRkQ5NXp0dmRjSkZmM1dnM00KLS0tIDNTbGxlUThFb3N2Z2xUb3FzUWFRQVpZakJtTy85dlRYVk5SenU4bytCZkEKajzSa7uTdcY7dP8vdcU2k9mKmuYys+MyhnMk1SX1qioKZO0wH4IBq42STETnfb1uJzw+9ccL/61L3IewycRaemhit4S2XKYubr8G+UbgclncthjyKQCsKKDvHWBWIXbM6Sfr58fzGHR9r9IfQ+2Fb9KD1Z+yzLnxc5qaiT1Yn7U=

It seems we have got a base64 encoded text as a reply. When decoded, it starts with `age-encryption.org/v1`, confirming that it has been encrypted with an age public key.

I used cyberchef to decode base64 from this, then save the output as a file. Then using the `Decrypt Binary` option in the age online tool, with our private key, we can decrypt this and get the text:
```
I told you I'd get it to you once we were on a secure line: sun{ag3_p1u5_tls_equalz_w3bs0ck3ts}
```


