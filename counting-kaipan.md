# counting

## by *kaipan*

### Description

This challenge just involves "guessing" a password, which is also the flag. We need to do some basic reverse engineering to figure out the program flow, but the whole principle around this challenge is instruction counting. Basically, whether a character in the password is correct hinges on the idea that they are processed differently. In other words, a character that is wrong instantly stops execution, while a character that is right gets processed by some extra code, and the difference in execution time between a wrong character and correct character are significant enough that it can be consistently measured to determine if the character you entered is correct or not. In this case, we can time the binary, and correct characters will make the binary take noticeably longer to execute vs. incorrect characters who take a shorter amount of time, and based on the time we can tell if each character in the password is in the correct position or not.

### Reverse Engineering Binary

To see how instruction counting comes into play, we need to do some basic reverse engineering. The `main` function is as follows:

```c
char cVar1;
char *pcVar2;
long in_FS_OFFSET;
char input_buffer [264];
long local_10;
  
local_10 = *(long *)(in_FS_OFFSET + 0x28);
printf("Enter the password: ");
fgets(input_buffer,0x100,stdin);
pcVar2 = strchr(input_buffer,L'\n');
*pcVar2 = '\0';
cVar1 = check_password(input_buffer);
if (cVar1 == '\0') {
  pcVar2 = "Wrong\n";
}
else {
  pcVar2 = "Correct!\n";
}
printf(pcVar2);
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                  /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
return 0;
```

The important bits are that we are asked to enter a password (no buffer overflow unfortunately). Then, the binary finds the newline character in the input with `strchr` and then replaces it with the null-terminator character. Then we make a call to `check_password` and the return value of `check_password` determines if the password is correct or not; `check_password` is as follows:

```c
char cVar1;
size_t sVar2;
int local_1c;
  
local_1c = 0;
while( true ) {
  sVar2 = strlen(param_1);
  if (sVar2 <= (ulong)(long)local_1c) {
    sVar2 = strlen(param_1);
    return sVar2 & 0xffffffffffffff00 | (ulong)(sVar2 == 0x1c);
  }
  cVar1 = check_char(local_1c,param_1);
  if (cVar1 != '\x01') break;
  local_1c = local_1c + 1;
}
return 0;
```

Essentially, this code checks if the password is 28 characters in length, which is when it will return true (1) and stop the infinite loop (if we recall the `main` function source code, a return value of 1 ends up printing "Correct!\n"). Then for each character in the password, we call `check_char` and the return value of `check_char`, if the character in the password is incorrect, will cause us to break from the loop and then return 0 (and back in `main` the integer 0 when casted to a character becomes the null-terminator, so the conditional right after will see that the return value is equal to the null-terminator and print "Wrong\n", telling us that the password is wrong). Here is `check_char`:

````c
char cVar1;
ulong uVar2;
  
cVar1 = password[param_1];
uVar2 = mangle_char(param_1,param_2);
return uVar2 & 0xffffffffffffff00 | (ulong)(cVar1 == (char)uVar2);
````

Essentially, we take the character at the current index of the password that we entered, and we also mangle the character at the current index of the password by calling `mangle_char` and we return whether the password and the mangled character match. The return value then affects whether or not the infinite loop in `check_password` is broken out of and subsequently whether the password is correct or not. The actual code of `mangle_char` doesn't really matter, the only thing we need to know is that it does a lot of operations such that when we measure the execution time of the binary, we can see that this function makes the execution time if the binary longer and aids us in determining whether the password is correct or not through the execution time as stated in the description. The execution time gets longer because as the password becomes more and more correct, you run the `mangle_char` function more and more and the execution time gets noticeably longer and longer, whereas incorrect passwords will break from the `check_char` and `mangle_char` loop and their execution times will be shorter.

### Automate Password Guess and Check

We can now see how to guess the password; we can just check each character that we think will be in the password, which in this case is also the flag, which is likely all the printable ASCII characters. For each character that we check we run the program and measure the execution time. After we tried all the characters we compare their times, and the one that takes the longest is the correct character. Once we get the first correct character we then guess all the possible second characters and measure the time, and then again take the longest execution time as the correct password. We just repeat and progressively build up the correct password by taking the longest execution time as the correct password.

Since we are lazy, we can use tools already developed for this kind of task, including but not limited to *Intel's Pin Tool* for instruction counting (wrapped by PinCTF script for CTF purposes), and *Instruction Stomp*. We just need to make sure that the scripts are configured properly like sending newline characters to the binary for every password, since if we refer back to the source code, the newline gets converted to the null-terminator so that the input string can be processed properly (and also why we didn't get first blood :pensive:). Besides that we just run the scripts and get the password/flag once we guess 28 characters correctly as indicated by the source code earlier.

### Flag

`osu{1ts_ju5t_a5_3z_4s_1_2_3}`