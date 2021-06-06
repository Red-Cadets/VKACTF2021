from functools import *
from Crypto.Util.number import *
from math import gcd


def lcg(m, a, c, x):
	return (a*x + c) % m

def crack_unknown_increment(states, modulus, multiplier):
	increment = (states[1] - states[0]*multiplier) % modulus
	return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
	multiplier = (states[2] - states[1]) * inverse(states[1] - states[0], modulus) % modulus
	return crack_unknown_increment(states, modulus, multiplier)


def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

ticket1 = [62703, 49426, 15808, 27261]
ticket2 = [15883, 28680, 40109, 17791]

l = ticket1 + ticket2
m, a, b = crack_unknown_modulus(l)

x = l[7]
for _ in range(4):
    x = (a * x + b) % m
    print(x)
