# babypwn

## by *kaipan*

### Decompilation

Upon decompilation in Ghidra, we start our inspection of the binary in the `main` function. There is nothing of note here except for the call to `user_input`. We investigate the `user_input` function and find that there a few local variables in the function (depends on the version of Ghidra). The older versions of Ghidra had three local variables in the function, while the latest version (version 10) that I used to do this writeup correctly had 2 local variables in the function. We come to find out that these local variables are really just references to different parts of a contiguous memory block. In other words, these local variables are really different parts of an array. Adding up all the sizes of the local variables give us 16 bytes total, meaning that the array is 16 bytes long. If you look for where this array is used, it is used as an argument for `fgets` which is for getting user input. We can infer that this is a buffer that holds user input, meaning that the array is a character array 16 bytes long (a character is 1 byte so it holds 16 bytes). Unfortunately, for anyone using an **older version of Ghidra, the size of these local variables (that are really just parts of an array) add up to 20 bytes, which is incorrect**. You had to look at disassembly in *pwndbg* or manually enter input and find where the input is stored using *pwndbg*. This disassembly should indicate that the buffer passed to `fgets` is offset of then pushed RBP register by 16 bytes (RBP-0x10), meaning that the buffer is 16 bytes long (it holds up to 16 characters and then reaches the saved RBP location in memory). Manually checking *pwndbg* should also turn up similar results, we can get the address of the saved RBP value in memory, and then enter some sort of string for the `fgets` that is easy to distinguish in memory (like a string of A's). We can use *pwndbg*'s memory viewing command `x` to examine the memory and find where our string is stored in memory (find the A character bytes in memory for our case). Once we find the location in memory where the buffer starts storing the characters we entered, we can take that base address of the buffer and subtract it from the address of saved RBP earlier; this will tell us the distance between the start of the buffer and RBP, which should also be 16 bytes, indicating that the buffer is 16 bytes long.

Now we know that the buffer is 16 bytes long, what's next? Well looking back at at the `fgets` function, we realize that it is reading up to 200 bytes of data (200 characters), even though our buffer can only store 16 characters. This is indicative of a buffer overflow attack. We can use the fact that `fgets` reads more characters in then we can store to overwrite memory on the stack. We can fill up the 16 characters in the buffer, and use the remaining characters to overwrite memory like the saved RBP value on the stack and even the return address of the `user_input` function (we put the return address of `user_input` on the stack so that the binary can return to the next instruction after the call to `user_input` to continue running the program). We can exploit the return address to return to another function rather than the normal return to the instruction after the call to `user_input`. If we look through all the functions in the binary, we find an interesting `print_flag` function that we could perhaps run by returning to the address of `print_flag` from overwriting the return address of `user_input` to get the flag for the challenge...

We can obtain the address of `print_flag` through two methods that I will discuss. We can have *pwntools* find it for us painlessly in our Python script, or we can do the dirty work and find it ourselves with *pwndbg*. The former will be demonstrated in the script used to exploit the binary, while the latter can be done by running *pwndbg* with the binary loaded and then running the `print print_flag` command to get *pwndbg* to print all the information about the function, including its address (*0x400687*). Now we know everything necessary to create our exploit script!

### Stack Diagram

In order to fully understand the script and what is being overwritten in the stack, I have made this stack diagram that displays the state of the stack in the `user_input` function (I only include all the important parts needed for the exploit to keep it simple).

Note: this is a 64-bit binary, so memory is in "chunks" of 8 bytes, thus `[             ]` will represent 8 bytes of memory.

```
[ return addr ] <-- return addr of user_input that we overwrite with print_flag's addr
[  saved RBP  ] <-- saved stack frame base, used for offsetting to local variables and function arguments (assembly)
[             ] <-- ending 8 bytes of buffer
[    buffer   ] <-- starting 8 bytes of buffer
```

We see that we need to fill the 16 bytes of buffer, then overwrite the 8 bytes of saved RBP, before we get to the return address of `user_input`. We then need another 8 bytes to overwrite the return address. For the sake of clarity, I overflowed saved RBP with a 8 character string 'SSSSSRBP' in my script to keep track of where RBP is in the payload, but this is not necessary, and you can just flood saved RBP with 25 characters total to reach the return address and then overwrite the return address with an additional 8 bytes to return to `print_flag`. The script also gets the address of `print_flag` which I will comment in the script.

### *pwntools* Script

```python
from pwn import *

p = remote('chal.ctf-league.osusec.org', 4747)

# Load binary ELF to get the address of print flag through symbols dictionary
e = ELF("./babypwn")
print_flag = e.symbols['print_flag']

# Overwrite the buffer with 16 A's and then saved RBP with 'SSSSSRBP'
payload = b'A' * 16 + b'SSSSSRBP'
# Overwrite return addr of user_input with address of print_flag
payload += p64(print_flag)

p.sendline(payload)

p.interactive()

```

### Flag

`osu{c0ngr4tz_on_F1r5T_pwn}`