# KidExchange

## Problem statement

We are given [alice.py](./alice.py) and [bob.py](./bob.py),
which is the code two parties communicating over a channel run.
Additionally, we have a [Wireshark dump](./capture.pcapng) of their communications.

The task is to recover the flag from the said dump.

## Analysis

We notice that Alice and Bob use a bespoke system based on modular arithmetic,
which means we can probably break it with some number theory.

Our goal is to emulate Bob, who decrypts the flag received from Alice.
Bob does the following:
```py
k = pow(e4, e7, m)
key = int.to_bytes(k, 16, 'big')
```
so it seems that we need `e4` and `e7`, but not necessarily anything else. Now,
```py
e4 = pow(3, p3 * e3, m) = pow(3, p3 * (p3 + 4 * p4) % m, m)
```
by expanding `e3`, so we can recover `e4` easily just from `p3` and `p4`,
which are available to us: Bob receives them from Alice.
The other part is harder:
```py
e7 = (e5 + 4 * e6) % m =  (e1**4 + 4 * e2**4) % m
```
However, `e1` and `e2` are never sent over the channel,
and we come up short trying to find a number-theoretic way of recovering them from `p1` and `p2`:
```py
p1 = (e1**2 - 2 * e1 * e2 + 2 * e2**2) % m
p2 = (e1 * e2) % m
```
Maybe we could do something is `p1 = (e1 - e2)**2 % m` held, but the pesky factor of `2` before `e2**2`
prevents this. Fortunately, there is a much easier path for us to take,
which we find after a sufficient amount of staring at the equations:
```py
e7 = p1 ** 2 + 4 * p2 * (p1 + p2) - 4 * p2**2
```
Verifying the expansion is straightforward, but tedious.
In any case, we now have `e4` and `e7` as needed, derived entirely from the captured data.

## Solution

```py
from binascii import unhexlify

from sage.all import *
from Crypto.Cipher import AES

def main():
    n = 128
    m = 2**128
    R = Zmod(m)

    p1 = R(273788890796601263265245594347262103880)
    p2 = R(258572069890864811747964868343405266432)
    p3 = R(26837497238457670050499535274845058824)
    p4 = R(40856090470940388713344411229977259912)
    with open("payload") as f:
        cont = unhexlify(f.read().strip())

    e3 = p3 + 4 * p4
    e4 = power_mod(3, ZZ(p3) * ZZ(e3), m)
    e7 = p1 ** 2 + 4 * p2 * (p1 + p2) - 4 * p2**2

    k = power_mod(ZZ(e4), ZZ(e7), m)
    key = int(k).to_bytes(16, 'big')

    cipher = AES.new(key, AES.MODE_ECB)

    print(cipher.decrypt(cont).decode('utf-8'))

if __name__ == "__main__":
    main()
```
