# DAT - Distributed Access Token

## Document

### [DAT Run Online](https://dat.saro.me)

### [What is DAT](https://dat.saro.me/--/intro)

### [Go Example](https://dat.saro.me/--/libs/go-saro-dat)

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
plain: f8ihvaSeSqtgjg2b44ZfLC5u9V0OjupYaXoHWWuU3zUA0uqdbF6TSL7j0YZzQ6o1HdSfpG7eohw6crfR3R3JRDlPKa6XA17Aa8z8
secure: DDaZ5HUybJwGtTdKkeRAjIBcsxLZ2VUt5P4seQDrTLLdaP3HbgqHNfVG0Gj2fULozB35ejk5I1WYavj4cMSIcsYKyTASpXIMNHQj

Multi-Thread
HMAC-SHA256-MFS IV-AES128-GCM Issue * 10000 : 19ms
HMAC-SHA256-MFS IV-AES128-GCM Parse * 10000 : 7ms
HMAC-SHA256-MFS IV-AES256-GCM Issue * 10000 : 13ms
HMAC-SHA256-MFS IV-AES256-GCM Parse * 10000 : 7ms
HMAC-SHA384-MFS IV-AES128-GCM Issue * 10000 : 13ms
HMAC-SHA384-MFS IV-AES128-GCM Parse * 10000 : 7ms
HMAC-SHA384-MFS IV-AES256-GCM Issue * 10000 : 13ms
HMAC-SHA384-MFS IV-AES256-GCM Parse * 10000 : 7ms
HMAC-SHA512-MFS IV-AES128-GCM Issue * 10000 : 14ms
HMAC-SHA512-MFS IV-AES128-GCM Parse * 10000 : 8ms
HMAC-SHA512-MFS IV-AES256-GCM Issue * 10000 : 16ms
HMAC-SHA512-MFS IV-AES256-GCM Parse * 10000 : 8ms
ECDSA-P256 IV-AES128-GCM Issue * 10000 : 61ms
ECDSA-P256 IV-AES128-GCM Parse * 10000 : 73ms
ECDSA-P256 IV-AES256-GCM Issue * 10000 : 55ms
ECDSA-P256 IV-AES256-GCM Parse * 10000 : 70ms
ECDSA-P384 IV-AES128-GCM Issue * 10000 : 214ms
ECDSA-P384 IV-AES128-GCM Parse * 10000 : 575ms
ECDSA-P384 IV-AES256-GCM Issue * 10000 : 219ms
ECDSA-P384 IV-AES256-GCM Parse * 10000 : 574ms
ECDSA-P521 IV-AES128-GCM Issue * 10000 : 476ms
ECDSA-P521 IV-AES128-GCM Parse * 10000 : 1573ms
ECDSA-P521 IV-AES256-GCM Issue * 10000 : 503ms
ECDSA-P521 IV-AES256-GCM Parse * 10000 : 1485ms

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
HMAC-SHA512-MFS IV-AES128-GCM Parse * 10000 : 9ms
HMAC-SHA512-MFS IV-AES256-GCM Issue * 10000 : 15ms
HMAC-SHA512-MFS IV-AES256-GCM Parse * 10000 : 10ms
ECDSA-P256 IV-AES128-GCM Issue * 10000 : 175ms
ECDSA-P256 IV-AES128-GCM Parse * 10000 : 363ms
ECDSA-P256 IV-AES256-GCM Issue * 10000 : 170ms
ECDSA-P256 IV-AES256-GCM Parse * 10000 : 364ms
ECDSA-P384 IV-AES128-GCM Issue * 10000 : 1105ms
ECDSA-P384 IV-AES128-GCM Parse * 10000 : 3254ms
ECDSA-P384 IV-AES256-GCM Issue * 10000 : 1105ms
ECDSA-P384 IV-AES256-GCM Parse * 10000 : 3254ms
ECDSA-P521 IV-AES128-GCM Issue * 10000 : 2707ms
ECDSA-P521 IV-AES128-GCM Parse * 10000 : 8584ms
ECDSA-P521 IV-AES256-GCM Issue * 10000 : 2719ms
ECDSA-P521 IV-AES256-GCM Parse * 10000 : 8564ms
```
