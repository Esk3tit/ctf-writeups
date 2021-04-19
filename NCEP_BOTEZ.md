# NCEP_BOTEZ Any% Speedrun
### By kaipan	🇺🇸 PC	24m 31s	4/19/2020

The first thing to realize is that the flag is loaded into a buffer in memory. The address of the buffer is given when we run the binary.

We use Ghidra to take a look at the decompiled code of the binary. We see that we allocate memory to a variable, and then offsets of this one variable is used throughout the code. This indicates that the variable must either be some sort of collection type like an array, or it could be a "packed" struct. Arrays contain elements of the same type, while members of a struct can have different types, so we look at all the places where the main variable is used (or an offset of that variable) to determine the types of the variable/offsets. Looking through the launch_gnuchess function, we see that there are file descriptor functions being used. This indicates that **int** is a type that is used. We also see that in the main function, the offset of the main variable is used in a printf statement as a **string**; since there are differing types, we can conclude that the main variable is a **struct**.

**THE MAIN GOAL THEN IS TO OVERWRITE THE STRING MEMBER THAT IS BEING PRINTED TO THE SCREEN WITH THE FLAG STORED IN THE BUFFER WHOSE ADDRESS IS GIVEN TO US**

If we do so, then the flag would take the place of the content in the string member and the flag gets printed by the printf statement.

We dig deeper into the code, and inside the thread handler function, we find that two threads are created. One is for asynchronous input and the other is for asynchronous output. We can use the input buffer used by async input to do a buffer overflow to essentially overwrite the printed string with the flag. The first thing we do is to find the offset from the input buffer to the string member. We see from the code that the buffer is at `0x110` while the string member is offset at `0x210`. So we take the difference to find the offset (`0x210 - 0x110`). 

We now create the payload to overflow by packing the address given for the flag with **p64()** from pwn. The script just packs the address repeatedly until we ge to the string member where we overwrite the contents with the address of the flag. The script is shown below:

```python
from pwn import *
p = remote('ctf-league.osusec.org', 31315)
print(p.recvuntil(b'flag loaded at ').decode())
addr = int(p.recvline().decode()[2:], 16)
print(hex(addr))
offset = 0x210 - 0x110
payload = p64(addr)*(offset // 8) + p64(addr)
print(payload)
print(p.recv().decode())
p.sendline(payload)
p.interactive()
```

We run the script and get the flag:

`osu{ro$eN_w1LL_not_8e_th1$_4givinG}`
