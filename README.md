# DAT - Distributed Access Token

## Document

### [DAT Run Online](https://dat.saro.me)

### [What is DAT](https://dat.saro.me/intro)

### [Go Example](https://dat.saro.me/libs/go-saro-dat)

## Support algorithm
### Signature
| name            | note                  |
|-----------------|-----------------------|
| ECDSA-P256      | = secp256r1           |
| ECDSA-P384      | = secp384r1           |
| ECDSA-P521      | = secp521r1           |
| HMAC-SHA256-MFS | = 256Bit Fixed Secret |
| HMAC-SHA384-MFS | = 384Bit Fixed Secret |
| HMAC-SHA512-MFS | = 512Bit Fixed Secret |
- MFS : Maximum(Same Bit) Fixed Secret

### Crypto
| name       | note                          |
|------------|-------------------------------|
| IV-AES128-GCM | (IV=NONCE:96BIT) + AES128 GCM |
| IV-AES256-GCM | (IV=NONCE:96BIT) + AES256 GCM |


# Performance
- random plain and secure test
- mac mini m4 2024 basic (10 core)
- [bench_test.go](bench_test.go)
```
=== RUN   TestBenchmark
performance test (plain, secure)
plain: ZOX8UmAH0U1jylVzwd4zNWEuH3cBSP5SOTeaBXTiL3894Kbhr48Su6aABNkDcoW55KfEZWRCKR8ewxMerY66mcIkFnCLrg59VSjT
secure: poQnpcoCdoSOLND8s1YaOhxxwJ080ovy3DotHDZy7Txiwg0hUJlZABI1Bi4Wbag9RjCR61fPhMRDpra3H5u4lANE0OJZqrZ6cG0M

Multi-Thread
HMAC-SHA256-MFS IV-AES128-GCM Issue * 10000 : 19ms
HMAC-SHA256-MFS IV-AES128-GCM Parse * 10000 : 8ms
HMAC-SHA256-MFS IV-AES256-GCM Issue * 10000 : 16ms
HMAC-SHA256-MFS IV-AES256-GCM Parse * 10000 : 7ms
HMAC-SHA384-MFS IV-AES128-GCM Issue * 10000 : 14ms
HMAC-SHA384-MFS IV-AES128-GCM Parse * 10000 : 7ms
HMAC-SHA384-MFS IV-AES256-GCM Issue * 10000 : 14ms
HMAC-SHA384-MFS IV-AES256-GCM Parse * 10000 : 7ms
HMAC-SHA512-MFS IV-AES128-GCM Issue * 10000 : 14ms
HMAC-SHA512-MFS IV-AES128-GCM Parse * 10000 : 7ms
HMAC-SHA512-MFS IV-AES256-GCM Issue * 10000 : 14ms
HMAC-SHA512-MFS IV-AES256-GCM Parse * 10000 : 7ms
ECDSA-P256 IV-AES128-GCM Issue * 10000 : 57ms
ECDSA-P256 IV-AES128-GCM Parse * 10000 : 71ms
ECDSA-P256 IV-AES256-GCM Issue * 10000 : 56ms
ECDSA-P256 IV-AES256-GCM Parse * 10000 : 66ms
ECDSA-P384 IV-AES128-GCM Issue * 10000 : 202ms
ECDSA-P384 IV-AES128-GCM Parse * 10000 : 565ms
ECDSA-P384 IV-AES256-GCM Issue * 10000 : 215ms
ECDSA-P384 IV-AES256-GCM Parse * 10000 : 545ms
ECDSA-P521 IV-AES128-GCM Issue * 10000 : 448ms
ECDSA-P521 IV-AES128-GCM Parse * 10000 : 1381ms
ECDSA-P521 IV-AES256-GCM Issue * 10000 : 450ms
ECDSA-P521 IV-AES256-GCM Parse * 10000 : 1405ms

Single-Thread
HMAC-SHA256-MFS IV-AES128-GCM Issue * 10000 : 12ms
HMAC-SHA256-MFS IV-AES128-GCM Parse * 10000 : 6ms
HMAC-SHA256-MFS IV-AES256-GCM Issue * 10000 : 11ms
HMAC-SHA256-MFS IV-AES256-GCM Parse * 10000 : 6ms
HMAC-SHA384-MFS IV-AES128-GCM Issue * 10000 : 15ms
HMAC-SHA384-MFS IV-AES128-GCM Parse * 10000 : 10ms
HMAC-SHA384-MFS IV-AES256-GCM Issue * 10000 : 15ms
HMAC-SHA384-MFS IV-AES256-GCM Parse * 10000 : 10ms
HMAC-SHA512-MFS IV-AES128-GCM Issue * 10000 : 15ms
HMAC-SHA512-MFS IV-AES128-GCM Parse * 10000 : 10ms
HMAC-SHA512-MFS IV-AES256-GCM Issue * 10000 : 15ms
HMAC-SHA512-MFS IV-AES256-GCM Parse * 10000 : 10ms
ECDSA-P256 IV-AES128-GCM Issue * 10000 : 178ms
ECDSA-P256 IV-AES128-GCM Parse * 10000 : 367ms
ECDSA-P256 IV-AES256-GCM Issue * 10000 : 167ms
ECDSA-P256 IV-AES256-GCM Parse * 10000 : 364ms
ECDSA-P384 IV-AES128-GCM Issue * 10000 : 1105ms
ECDSA-P384 IV-AES128-GCM Parse * 10000 : 3255ms
ECDSA-P384 IV-AES256-GCM Issue * 10000 : 1108ms
ECDSA-P384 IV-AES256-GCM Parse * 10000 : 3250ms
ECDSA-P521 IV-AES128-GCM Issue * 10000 : 2685ms
ECDSA-P521 IV-AES128-GCM Parse * 10000 : 8812ms
ECDSA-P521 IV-AES256-GCM Issue * 10000 : 2699ms
ECDSA-P521 IV-AES256-GCM Parse * 10000 : 8779ms
```
