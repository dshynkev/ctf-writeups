# notbefooled

## Problem statement

In this task, we are talking to a service with the following code:
```py
from sage.all import *
from threshold import set_threshold
import random

FLAG = open("/flag", "r").read()


def launch_attack(P, Q, p):
    E = P.curve()
    Eqp = EllipticCurve(Qp(p, 8), [ZZ(t) for t in E.a_invariants()])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p * P_Qp
    p_times_Q = p * Q_Qp

    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()

    phi_P = -(x_P / y_P)
    phi_Q = -(x_Q / y_Q)
    k = phi_Q / phi_P

    return ZZ(k) % p


def attack(E, P, Q):
    private_key = launch_attack(P, Q, E.order())
    return private_key * P == Q


def input_int(msg):
    s = input(msg)
    return int(s)


def curve_agreement(threshold):
    print("Give me the coefficients of your curve in the form of y^2 = x^3 + ax + b mod p with p greater than %d:" % threshold)
    a = input_int("\ta = ")
    b = input_int("\tb = ")
    p = input_int("\tp = ")
    try:
        E = EllipticCurve(GF(p), [a, b])
        if p >= threshold and E.order() == p:
            P = random.choice(E.gens())
            print("Deal! Here is the generator: (%s, %s)" % (P.xy()[0], P.xy()[1]))
            return E, P
        else:
            raise ValueError
    except Exception:
        print("I don't like your curve. See you next time!")
        exit()


def receive_publickey(E):
    print("Send me your public key in the form of (x, y):")
    x = input_int("\tx = ")
    y = input_int("\ty = ")
    try:
        Q = E(x, y)
        return Q
    except TypeError:
        print("Your public key is invalid.")
        exit()


def banner():
    with open("/banner", "r") as f:
        print(f.read())


def main():
    banner()
    threshold = set_threshold()
    E, P = curve_agreement(threshold)
    Q = receive_publickey(E)
    if attack(E, P, Q):
        print("I know your private key. It's not safe. No answer :-)")
    else:
        print("Here is the answer: %s" % FLAG)


if __name__ == "__main__":
    main()
```
In other words, we have the following setting:
1. Server chooses and sends a large `threshold` (consistently `threshold > 2**200`).
2. Client chooses and sends `a`, `b`, and `p`,
   which define an elliptic curve `E(x) = x^3 + ax + b` over `Z/pZ`.
3. Server verifies that `a`, `b` define an elliptic curve and that
  a. `p >= threhold`
  b. `E.order() == p`.
4. Server chooses and sends a generator `P` of `E`.
5. Client chooses a private key `k` and sends the respective public key `Q = k * P`.
6. Server mounts an attack.
   The client gets the flag if the attack **fails** to recover the private key `k`.

## Analysis

It is reasonably easy to find that curves for which 3b holds are called **anomalous**
and have interesting properties: in particular, they are weak to a so-called Smart's attack [[1]](#References),
which is exactly what `launch_attack` here implements.

In a nutshell, a curve `E` over `Zmod(p)` can be _lifted_
to a curve `E` over the p-adic rationals `Qp(p)`.
This lift is a homomorphism with respect to multiplication,
and it turns out that ECDLP is easy over `Qp(p)`.

Popular literature generally does not mention any failure modes of this attack:
this is because, in a sense, it "doesn't have any":
a _sufficiently smart_ implementation will succeed against every anomalous curve.

So the flaw must be in the implementation, and [[2]](#References) points in the same direction:
the same code as `launch_attack`, given in that post, fails in the case
where
```py
EllipticCurve(Qp(p, 8), [ZZ(t) for t in E.a_invariants()])
```
gives a **canonical lift** of `E` from `Zmod(p)` to `Qp(p)`.
It turns out Smart's original paper [[3]](#References) mentions this fact in passing.
It is not significant in general because a smart implementation will try random lifts:
```py
EllipticCurve(Qp(p, 8), [ZZ(t) + randint(0,p)*p for t in E.a_invariants()])
```
until it succeeds.
A randomly chosen lift has a `1/p` chance of failing, which is negligible.

So our goal is to exploit the fact that our adversary only tries
the trivial lift: the one with the same `a`-invariants as the original curve.
This is where this challenge became difficult:
my mathematical background was insufficient to exploit this.
There is a fairly detailed explanation [[4]](#References) of how to generate general anomalous curves,
but it is not clear which additional constraints are needed to ensure that the trivial lift is canonical.

In the end, I consulted an authority in the field, who pointed me to the fact that a zero `j`-invariant
(like in [[2]](#References)) together with a more careful choice of `p` (`27 * m**2 + 1`) is sufficient.
Note that this is essentially the `D = 3` case from [4], which is disregarded there
as an edge case (formulae differ when `j = 0`).

## Solution

```py
import math
import random

from sage.all import *
from pwn import *


def curve_from_prime(p):
    # a = 0 ensures j-invariant zero.
    # Don't know a smarter way to choose b...
    while True:
        b = random.randint(1, p-1)
        print(f"try b = {b}")
        E = EllipticCurve(GF(p), [0, b])
        if E.order() == p:
            print(f"chose b = {b}")
            return E


def anomalous_prime(pmin):
    k = int(math.log2(pmin)) + 1
    m = 2**(k//2)
    while True:
        print(f"try m = {m}")
        p = 27 * m**2 + 1
        if p % 4 == 0:
            p = ZZ(p // 4)
            if p.is_prime():
                print(f"chose p = {p}")
                return p
        m += 1


def main():
    r = remote("notbefoooled.challenges.ooo", 5000)
    r.recvuntil("greater than ")
    pmin = int(r.recvline()[:-2])
    print(f"requiring p >= {pmin}")

    p = anomalous_prime(pmin=pmin)
    E = curve_from_prime(p)
    a, b = E.a4(), E.a6()

    r.sendlineafter("a = ", str(a))
    r.sendlineafter("b = ", str(b))
    r.sendlineafter("p = ", str(p))
    
    r.recvuntil("the generator: (")
    gen_x = r.recvuntil(",")[0:-1]
    gen_y = r.recvuntil(")")[1:-1]
    gen = E(int(gen_x), int(gen_y))
    
    priv = random.randint(1, p-1)
    pub = priv * gen
    pub_x, pub_y = pub.xy()
    
    r.sendlineafter("x = ", str(pub_x))
    r.sendlineafter("y = ", str(pub_y))

    print(r.recvall())


if __name__ == "__main__":
    main()
```

## References

[1] https://wstein.org/edu/2010/414/projects/novotney.pdf

[2] https://crypto.stackexchange.com/q/70454

[3] https://link.springer.com/content/pdf/10.1007/s001459900052.pdf

[4] http://www.monnerat.info/publications/anomalous.pdf
