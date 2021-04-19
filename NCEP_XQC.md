# NCEP_XQC Any% Speedrun
### By kaipan	🇺🇸 PC	14m 16s	4/19/2020

This binary was relatively simple compared to the second binary.
When we run the binary, we get the following prompt:

> Please enter your custom command line arguments, or just hit enter to begin your training:

If we hit enter, then the binary runs GNUchess. GNUchess will execute regardless, but we can exploit the fact that it gives us the chance to run our own command by adding another command onto the command that runs GNUchess. In this case, to run another command, we use the **&&** operator. So it first runs GNUchess, once we quit GNUchess, it should automatically run the second command specified after the operator. We have it run the **ls** command afterwards so we can scout out the machine and see if we can find a flag.

The result of **ls**:
chess
flag

We can see that there is a flag file, so all we need to do now is to print out the flag using the **cat** command which we run after GNUchess:

`&& cat flag`

And we get the flag!!!!

`osu{WeLc0m3_T0_tH3_c0LLe6e_0f_pWN}`

Short and sweet!

