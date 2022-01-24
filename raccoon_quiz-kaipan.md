# raccoon_quiz

## by *kaipan*

### Description

This is a pwn challenge. We first decompile the binary to understand the program.

### Decompilation

We immediately take a look at the `main` function to start tracing the execution of the binary. The `main` function calls `raccoon_quiz`. Taking a look at `raccoon_quiz` we see that it is just a standard quiz function. It asks the user three questions and counts the number of questions that the user gets correct in a variable. But since we have the decompilation, we can see the conditionals that check for the correct answer, prints out the fact that we got the right answer, and increments the correct answer counter (each user input per question gets compared against the correct answer string, so obviously we just need to enter that correct letter/char/string as input to get the question right)... From the condition, we see that the answers that increment the counter and are therefore correct are in the following order **A, B, A**. Looking further at the code, if we get all three questions correct, we can put our name on the leaderboard, otherwise we get some failure message and the program exits. Hmm, the program doesn't interact with the flag at all...

Now that we hit an execution dead-end, we decide to take a look at all the other functions in the decompilation, and we stumble across a very interesting function named `super_sneaky_function`. Definitely doesn't sound sussy at all... But on the bright side, we see that the `super_sneaky_function` actually reads and prints the flag!!! But how do we call this function if the natural execution flow of the binary program never calls it? We look back at `raccoon_quiz` for some potential exploits. The most obvious exploit we could use would be a buffer overflow exploit to overwrite the return address of `raccoon_quiz` to then return to and execute `super_sneaky_function`. Upon further inspection though, we see that the buffer is 528 bytes (from disassembly RBP-0x210) while the `fgets` call that writes user input to the buffer only writes 0x200 or 512 bytes, which is clearly not enough to overwrite the return address through a potential overflow since `fgets` doesn't read/write enough to overflow the buffer. But for all the pogchamps who have taken Cyber Attack and Defense (and the people who read the hint document), we find that there is a *format string vulnerability* in the program when the program prints out the congratulations message. The binary uses `printf` to print out our name variable whose value is dictated by user input, meaning we can control how `printf` executes. `printf` interprets special format specifiers like `%d` and `%x` differently from regular text in a string. I'm too lazy to fully describe what format string vulnerabilities are so you should go read up on them, but the gist of it is since we have `printf(name_buf);` in the code, it prints out whatever is stored in that buffer, but that buffer's content is controlled by our user input, so we can put in some format specifiers like `%x` and `%s` (through user input) to perform an arbitrary read from the stack or the `%n` specifier to perform an arbitrary write.

### Exploit

Now we need to start writing a script to take advantage of this format string exploit. We can't do return address overwrite since the binary actually calls exit at the end of `raccoon_quiz` so we won't return to anywhere. We look up the security measures of the binary with the *pwn checksec* command and find that there is Partial RELRO is enabled (which is responsible for getting addresses of functions dynamically). This allows us to overwrite certain GOT table entries so that when the addresses of specific functions are being resolved, we can make that function actually call another function because the GOT entry that dictates the address of the code for the function has been modified to point at a different function. We can then make an already existing function in the binary call the code of the `super_sneaky_function` to print the flag for us! Now we need to find the address of the GOT entry to write the address of `super_sneaky_function` to, and of course the address of `super_sneaky_function` itself. We can discover these in GDB or however you want to do it. For the GOT entry, we need to target a function's GOT address to overwrite. This function must be called after `printf` because `printf` must be called first to modify the GOT entry and then the function that we change the address for will redirect to `super_sneaky_function` if it gets called after our modification with `printf`. We choose the `exit` function, due to how addresses are evaluated dynamically. Essentially, the first time an external library function is called, the binary doesn't know the address of that function and must get it through the PLT and the linker/loader. Once the address is resolved, then lazy evaluation occurs and that address is saved in `.got.plt` so the PLT process doesn't need to happen again to reduce the overhead of having to look up the address this way each time the function is called and it jumps directly to the saved address the next time. Once an a function has been used once, its address is resolved and it directly jumps to the address already saved even if you overwrite the `.got.plt` entry afterwards. This is why we need to target a function that hasn't been called yet so that it resolves to our own modified address to `super_sneaky_function`, and thus we choose `exit` rather than `puts` since `puts` has been used earlier in the program and is already resolved. We thus find the GOT address of `exit`. Normally this arbitrary write process would be a lot more involved, but with the power of *pwntools* it does all of the heavy lifting for us. The last thing we need is the offset to the buffer from the current position in the stack, which we can find easily by putting some arbitrary characters like 'AAAAAAAA' at the start of your user input, and then providing a lot of `%x`'s afterwards for user input. This should get `printf` to read your user input as having all `%x` specifiers and start printing values on the stack. We look for the hexadecimal value of our arbitrary characters in the printed output (A = 0x41) and we find that the offset to the buffer is 6. Now we can finish the script.

### Script

The address for the GOT entry of exit is **0x602050** from address calculations or however you choose to do it; the address for `super_sneaky_function` to write to the address of the GOT entry is **0x400747** from GDB. The offset is 6. We need to keep in mind that we must answer the quiz questions correctly first before we get to the section with the format string vulnerability as well. Just run the script to get the flag!

```python
#!/usr/bin/env python3
from pwn import context, remote, process, log, gdb 
from pwnlib.fmtstr import fmtstr_payload

context(arch='amd64', os='linux', endian='little', log_level='info')
context.terminal = ["tmux", "splitw", "-h"]
p = remote("chal.ctf-league.osusec.org", 4816)
#p = process("./raccoon_quiz")
#gdb.attach(p)

p.sendline("A")
p.sendline("B")
p.sendline("A")

# overwrite GOT entry for exit with a pointer to the flag printing function
p.sendline(fmtstr_payload(6, {0x602050: 0x400747}))
p.interactive()
```

### Flag

`osu{tr4a5h_pr0gr4mm1ng_in_4_tr4sh_g4m3}`