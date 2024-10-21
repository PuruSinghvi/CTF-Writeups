## Name: Certified

## Description
?
## Files
[[server.pem]]

## Writeup
Reading the description tells us that the flag is given directly to us.

So I tried to directly base64 decode the certificate using cyberchef. Then looking at the strings we get an interesting one which seems to be base64 encoded string with some extra data around it:
`4c3Vue2IzdF91X2QxZG50X2tuMHdfYjB1dF9vMWRfbXNncyF9Cg==0`

Removing this extra data we get: `c3Vue2IzdF91X2QxZG50X2tuMHdfYjB1dF9vMWRfbXNncyF9Cg==`
Decoding it gives us the flag:
`sun{b3t_u_d1dnt_kn0w_b0ut_o1d_msgs!}`



