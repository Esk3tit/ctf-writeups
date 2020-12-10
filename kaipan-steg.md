# Stego Challenge: Russian Nesting Bathhouse

Ok so this is my first writeup for a challenge, so I don't have any idea how to specifically do a writeup, but I'll try my best.

First we are given a file named: _russian-nesting-bathhouse.zip_

After extracting everything (I'm on windows so 7-Zip gang), we get two files:

1. _bathhouse.zip_
2. _bathhouse_password_

We are given a clue in the prompt, it states that...
```
I recall storing the password as a PDF, and I xored it with a 4-byte repeating key (e.g. ab cd ef 01 ab cd ef 01 ...), but I forgot my key, and I cannot get it back :(.
Hint: you will not need to brute force this.
```

We know that the password is supposed to be in a PDF, so we utilize the concept of the `Magic number`.
A magic number is a constant numerical or text value used to identify a file format or protocol. In this case, the magic number for a PDF
is `hex 25 50 44 46`.

We use the program HexDump on the _bathhouse_password_ file and get the following starting hex values:
```
d6 df 47 2f
```

From the prompt we know that the password was xored with a 4-byte key, so we need to figure out what the key is that transformed the PDF magic number from `25 50 44 46` to `d6 df 47 2f`

Using the properties of xor and a xor calculator, we xor the magic number hex and the encrypted hex to find the key:
`25 50 44 46` ^ `d6 df 47 2f` = `f3 8f 03 69`
(If we xor the key with the magic number we get the encrypted hex string, so the result is the key)

We know that xor-ing can act as a "toggle", and so we can "toggle" the hex dump of the _bathhouse_password_ back and forth between decrypted and encrypted by xor-ing it with the key. We make a python script to do this.

```python
import sys

with open('bathhouse_password', 'rb') as f:
    bathhouse_enc = f.read()

key = bytes.fromhex('f3 8f 03 69')

size = len(bathhouse_enc);
bathhouse_dec = bytearray(size)

for i in range(size):
    bathhouse_dec[i] = bathhouse_enc[i] ^ key[i % len(key)]

with open('bathhouse_password.pdf', 'wb') as f:
    f.write(bathhouse_dec)
```

THe script reads in the bathhouse_password file in binary format and reads it, we then loop through the entire file to xor it with the repeating 4 byte key and then we write the result to a PDF.

The PDF provides the following password for the bathhouse.zip:
```
this_is_the_first_password_so_creative_right
```

We unzip the password locked zip file and get a new file: _polish_cow.mp3_

Upon playing the .mp3 file, we observed an odd looking cover image and a title that says `Why would someone hide a password in mp3 tags?`

In order to look at the tags and to also extract the cover image, I used a program called `MP3TAG` for Windows.

Loading the .mp3 into the program tells us that the composer tag holds the password: `p4$$w0Rd`
we also use the program to extract the cover image, which we call `00000000.jpg`

The program StegHide allows you extract data from an encrypted file, and the documentation shows that we need to enter a password.
Intuitively, we know that we need to use the password from the .mp3 tag for this purpose.

In a terminal, we run the extraction command:
```
.\steghide extract -sf 00000000.jpg -xf out -p 'p4$$w0Rd'
```

We get the output in the file out, using the `file <name>` command in a linux environment on the file shows that it is a gzip file.
So we extract the gzip file with a `tar -xvf out` command which gives us only the SECOND half of the flag in _flag_part_2.txt_

The first half of the flag is in the cover image; we analyze it using the StegSolve program. Upon inspection we can make out some parts of the flag in the image like `OSU{first_}`...

I tried using the stereogram solver to offset the image until the message was clear to no avail, so then I switched to looking at the various color channels of the image. Looking through the different channels gives us the different parts of the flag:
```
osu{first_
part_of_
7h15_flag
```

Intuitively, we combine all of these parts along with the second part of the flag from StegHide to get the final flag!!
```
osu{first_part_of_7h15_flag_dont_forget_5736h1d3}
```

Feels good man, and I didn't need to be carried for this challenge. I did a little carrying myself :)
(stegs are pretty cool, the idea of hiding on thing in another sounds kinda lit)