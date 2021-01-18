## Any% Cookie Writeup Speedrun

Objectives (there are two parts to the challenge):

 1. Beat the cookie clicker game by acquiring a whopping 18000000000000000000 cookies (I'm not going to bother to check how many zeroes that is for the numerical name).
 2. Do a buffer overflow to get the program to print the flag.

***Acquire the Cookies***
Now in theory, you could do this part legitimately by playing. Of course, it will take practically forever, and I'm an impatient man. The more practical way to get past this part, is to exploit it.
We first investigate the decompiled code. Although I won't put the pictures for this part for the sake of brevity, when we investigate the main function, we see that two threads are created, a **grandma_loop** and an **io_loop**, these are the functions that run until we meet the cookie requirement, and at that point the win function gets run (something that we also take note of).

We dive into both the grandma loop and the io loop. The grandma loop turns out to be insignificant, but when we look at the io loop we notice something interesting with how the program handles the choices that the user makes (like buying grandmas and upgrades). The loop validates user input (albeit it in a roundabout and kind of convoluted way in my opinion) but the important observation is that **the program DOES NOT check if you have a valid amount of currency to pay for your purchases!** 

This means that we can underflow the cookies we have and "wrap around" to the target value of the big number that we need to get to "win" by only buying. 2 out of the 3 purchasing options also end up generating cookies for you, so the most efficient choice is to improve grandma's baking rate (and not buy any grandmas). A quick calculation tells us that we need to buy the upgrade 51 times to underflow, so we create a python script to do this:

    #!/usr/bin/env python3
    
    from pwn import *
    from ctypes import *
    
    cdll.LoadLibrary("libc.so.6")
    ct_libc = CDLL("libc.so.6")
    
    p = remote("ctf-league.osusec.org", 31310)
    t = ct_libc.time(0)
    
    p.recvuntil(b'Enter any key to refresh')
    p.sendline('4' * 51)

***Overflow the buffer***
As a reward for exploiting cookie clicker, we get rewarded with yet another task that nobody saw coming. We first look at the **win** function we saw earlier. The function doesn't have any code that prints out the flag though, so we do some more digging and find a **print_flag** function that does exactly what we want. Now that we have the full picture, we know we need to perform a buffer overflow in the **win** function in order to overwrite its return address to the address of the **print_flag** function. We first find the address of the **print_flag** function with either the pwn library directly in the script, or in my case, with pwndbg/gdb's info function *print_flag*. The address is _0x0000000000400e9b_. We also notice that there is a stack cookie check, this stack cookie is assigned to a local variable, and that local variable is checked immediately after getting user input. If the local variable that we need to overflow over doesn't match the cookie. Then the program will crash. We need write the same value as stack cookie to the local variable when doing our buffer overflow.

We trace the origin of stack_cookie using Ghidra and we find that stack_cookie is assigned a random number from a random number generator seeded by the current time when the program was run. So we need to get the current time, seed the random number generator in our script, and generate our own matching stack cookie to bypass the stack_cookie check. Finally, we need to overwrite the RBP register (which we can overwrite with 8 bytes of anything) and then overwrite the return address with the address of **print_flag** which we found earlier.

The final part of the script:

    ct_libc.srand(t)
    stackcookie = ct_libc.rand()
    
    payload = b"A" * 28 + p32(stackcookie) + b"A" * 8 + p64(0x0000000000400e9b)
    p.send(payload)
    p.interactive()

When we run the script we get the flag. Hooray!

    osu{LAnC3_3a7s_0AtM3AL_ra1s1n}


 
