# DAT - Distributed Access Token

## Document

### [DAT Run Online](https://dat.saro.me)

### [What is DAT](https://dat.saro.me/--/intro)

### [Go Example](https://dat.saro.me/--/libs/go-saro-dat)

## support signature algorithm
| name   | algorithm  |
|--------|------------|
| P256   | secp256r1  |
| P384   | secp384r1  |
| P521   | secp521r1  |

## support crypto algorithm
| name       | algorithm                   |
|------------|-----------------------------|
| AES128GCMN | aes-128-gcm n(nonce + body) |
| AES256GCMN | aes-256-cbc n(nonce + body) |


# Performance
- random plain and secure test
- mac mini m4 2024 basic (10 core)
- [bench_test.go](bench_test.go)
```
=== RUN   TestBenchmark
performance test (plain, secure)
plain: BH62OXbOHIgMIRKvDyftUesEordnx4OcPQ20lGGRAbhWNgHYTgH8d9qA0Tdn7guU1JlzoGDNysQYoc8OQWXsyYLJJmeUXnHGocCg
secure: U8u73r1Cf7UBTOLVAVeDjVbRLj5ZV5zwepw8D0O04lh9Meg2vtKiauxYD2euVOwta2WaPzPbMKyteYzqx8cRDBolysRjCK5YE4zU

Multi-Thread
P256 AES128GCMN Issue * 10000 : 69ms
P256 AES128GCMN Parse * 10000 : 69ms
P256 AES256GCMN Issue * 10000 : 54ms
P256 AES256GCMN Parse * 10000 : 92ms
P384 AES128GCMN Issue * 10000 : 214ms
P384 AES128GCMN Parse * 10000 : 572ms
P384 AES256GCMN Issue * 10000 : 202ms
P384 AES256GCMN Parse * 10000 : 566ms
P521 AES128GCMN Issue * 10000 : 463ms
P521 AES128GCMN Parse * 10000 : 1494ms
P521 AES256GCMN Issue * 10000 : 496ms
P521 AES256GCMN Parse * 10000 : 1553ms

Single-Thread
P256 AES128GCMN Issue * 10000 : 179ms
P256 AES128GCMN Parse * 10000 : 381ms
P256 AES256GCMN Issue * 10000 : 178ms
P256 AES256GCMN Parse * 10000 : 366ms
P384 AES128GCMN Issue * 10000 : 1116ms
P384 AES128GCMN Parse * 10000 : 3261ms
P384 AES256GCMN Issue * 10000 : 1107ms
P384 AES256GCMN Parse * 10000 : 3252ms
P521 AES128GCMN Issue * 10000 : 2712ms
P521 AES128GCMN Parse * 10000 : 8918ms
P521 AES256GCMN Issue * 10000 : 2757ms
P521 AES256GCMN Parse * 10000 : 8721ms
```
