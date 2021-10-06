# Hash Browns

### Figuring Out How To Get In
This is a pretty simple challenge; the website states to inspect the button, and upon inspection using Firefox, we see that the button
has an onclick attribute that runs a check_password() event handler, which seems to be pretty interesting and might clue us in on the
password we need to enter. We can then go down into the script section of the interactive web inspector, which was pretty subtle and
I actually missed this during the challenge, or we can go to the cleaner looking static representation of the website's HTML by using
Firefox's view page source.

Regardless of how we find the script section of the HTML, we can see the source code for the check_password() event handler we noticed
earlier. We see that our password input gets passed into a SHA256 hash function, and then the resulting hash is compared directly
with another hash that represents the correct password, if the input hash and the correct password hash match then we are gaming and we can login to the system. All we need to do is then find a way to "reverse" this correct password hash
to find the password we need to enter.

### Getting In
Fortunately, the challenge website also provides another resource to use: CrackStation. It gives us the plaintext password if we provide
it a hash. We just enter in the correct password hash we found in the check_password() event handler and let it rip. Turns out
the password is `pineapple` and we enter this into the password field and submit to get into the mainframe.

### Flag
Now we just need to annoyingly catch a flag that is moving around on the screen. Copying it while moving is way too much work, so we open
inspect again and the HTML inspector actually displays the flag as part of the HTML anchor element, so we can just grab it from here and copy
it with far less work.

Flag:
`osu{p1n34ppl3_h45h_Br0wN5_4r3_g00D}`
