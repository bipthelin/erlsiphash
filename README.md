erlsiphash
========

Pure erlang implementation of the SipHash-2-4 algorithm.

SipHash computes 64-bit message authentication code from a variable-length
message and 128-bit secret key. It was designed to be efficient even for
short inputs, with performance comparable to non-cryptographic hash functions,
such as CityHash and MurmurHash thus can be used in hash tables to prevent
DoS collision attack (hash flooding) or to authenticate network packets.

Functions in SipHash family are specified as SipHash-c-d, where c is the
number of rounds per message block and d is the number of finalization rounds.
The recommended parameters are SipHash-2-4 for best performance,
and SipHash-4-8 for conservative security.

Currently only the SipHash-2-4 version is implemented.

Usage
-----

`siphash:hash(Msg, Key)` hash Message with the given Key.

``` erlang

1> siphash:hash("The quick brown fox jumps over the lazy dog", <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>).
5919806912997584868

```

