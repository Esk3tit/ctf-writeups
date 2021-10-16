# ultrasecure

### Decompilation
Upon decompiling the binary with ghidra, we find that the meat of the program is within one function called in main: password_check()
The function is for the most part pretty simple. The first part of the function is all variable declarations. Then we see usage of the
srand function and the time function, meaning that we generate a random number seeded by the system time. We see that the random number
is stored in a local variable and then printed to the screen. The user is supposed to enter this within .05 seconds (from running the program or observing that the decompiled code gets the time before and after your input to calculate how long it took and if it is not within .05 seconds then the program would quit), which for most people is impossible. This means that we have to use a script (pwntools lol) to enter in the input for us. We can simply get the random number printed to the screen through receiving output with pwntools, and then break the output string down to isolate the random number (split by space) to pass the random number back to the program as input with send.

We passed the first part of the challenge, we still have a second condition that we must pass before the print_flag() function is called.
We have to enter a second number, which is matched against the value of a local variable in the decompilation (we wouldn't know the value without decompilation as it is not printed when you run the program). We look at the decompilation and the number that we must enter as input
using pwntools is -0x21524cc1, the value of the local variable that is checked against our input. We take this number in its hex form and turn it into a string before sending it as input. The condition should pass and now the print_flag function should run if we connect pwntools to the remote environment!! (alternatively, you can convert the signed hex value to unsigned, which actually gives you 0xdeadb33f and you can turn it into a string and send it with pwntools and it should work as well)

### The Script
The script we used that implemented the above ideas in pwntools is below:

```python
from pwn import *

p = remote("chal.ctf-league.osusec.org", 4545)

line = p.recvline()

num = str(line).split(" ")[-1][:-3]

p.sendline(str(num).encode())

line2 = p.recvline()

print(line2)

answer = 0xdeadb33f

p.sendline(str(answer))

print(p.recvline())

# p.interactive()

#-559041729

#-0x21524cc1
```

### Flag
`osu{d3c0mp1ler_go_brrrr}`
