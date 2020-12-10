# many_time_pad Challenge Writeup Speedrun Any%

First we are presented with a website. The website tells us that it uses `One-time-Pad` as an encryption method, indicating that this is something that we should look
into in order to figure out how to decrypt whatever is needed. The website also provides the source code for the webserver. Most of the code in the source code
is actually irrelevant to the challenge, mostly serving pages and also exposing the encrpyting algorithm. The most important things to note are:

`The ciphertext will be returned in an HTML response header.`

```python
#secret admin page, the URL is the secret key so it is secure
@app.route("/" + cfg.secret_byte_string.decode())
def win():
    return(render_template("win.html"))
```

We know that we the overarching goal for this part of the challenge is to get the secret key, which takes us to the "win".

Upon reading up on the One-Time-Pad, we see that the XOR operation was used for the encryption of a one-time-pad. Knowing that 
`Plaintext XOR Key = Ciphertext` and `Plaintext XOR Ciphertext = Key`, we can find the secret key by encrypting plaintext of our choosing to
get the ciphertext, and then xor-ing the plaintext that we chose and the resulting ciphertext returned in the HTML response header to get the key.

I did this by using a string of 256 'a' characters as my plaintext, I took the ciphertext from the response header and made a python script to xor the two strings.

```python

str1 = b'\x08\x07L\x18\x0e\x14L\x15\x13\x08\x04\x05L\x15\x0eL\x05\x08\x13\x03\x14\x12\x15\x04\x13L\x15\t\x08\x12L\x13\x0e\x14\x15\x04L(L\x16\x08\r\rL\x07\x0e\x13\x16\x00\x13\x05L\x18\x0e\x14L\x15\t\x04L.242$"L 62L\x03\x08\r\rL\x0f\x04\x17\x04\x13L\x06\x0e\x0f\x0f\x00L\x06\x08\x17\x04L\x18\x0e\x14L\x14\x11L\x0f\x04\x17\x04\x13L\x06\x0e\x0f\x0f\x00L\r\x04\x15L\x18\x0e\x14L\x05\x0e\x16\x0fL\x0f\x04\x17\x04\x13L\x06\x0e\x0f\x0f\x00L\x13\x14\x0fL\x00\x13\x0e\x14\x0f\x05L\x00\x0f\x05L\x05\x04\x12\x04\x13\x15L\x18\x0e\x14L\x0f\x04\x17\x04\x13L\x06\x0e\x0f\x0f\x00L\x0c\x00\n\x04L\x18\x0e\x14L\x02\x13\x18L\x0f\x04\x17\x04\x13L\x06\x0e\x0f\x0f\x00L\x12\x00\x18L\x06\x0e\x0e\x05\x03\x18\x04L\x0f\x04\x17\x04\x13L\x06\x0e\x0f\x0f\x00L\x15\x04\r\rL\x00L\r\x08\x04L\x00\x0f\x05L\t\x14\x13\x15L\x18\x0e\x14LPSRUTWVY'
str2 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

#Decode
key = byte_xor(str1, str2.encode())

f = open("secretkey.txt", "w")
f.write(key.decode())
f.close()

```

When I checked my `secretkey.txt` file, the secret key was
`if-you-tried-to-dirbuster-this-route-I-will-forward-you-the-OSUSEC-AWS-bill-never-gonna-give-you-up-never-gonna-let-you-down-never-gonna-run-around-and-desert-you-never-gonna-make-you-cry-never-gonna-say-goodbye-never-gonna-tell-a-lie-and-hurt-you-12345678`

The next part of the challenge is a basic buffer overflow.

We are given a script that will do the hardwork for us, all we need to do is provide the script with information, specifically these three fields:

```python
#FILL OUT THESE THREE
buffer_size =
addr_of_printflag_function = 
secret_key_string =
```

We know the secret key string from the previous part, so we simply paste it there. For the buffer size, we use ghidra. In the decompiler, we see am fgets function
in the main function that gets user input for the prompt. We trace the buffer where the user input will stored back up and we see a character array that holds 16 characters. This is the size of the buffer, so we plug that into the script. Lastly, the website hints that we should use gdb to find the address of the print_flag
function. We do so using gdb's `info address` command, `info address print_the_flag` gives us an address and we plug that into the script as well.

Our script now has the fields filled out:

```python
#FILL OUT THESE THREE
buffer_size = 16
addr_of_printflag_function = 0x400647
secret_key_string = 'if-you-tried-to-dirbuster-this-route-I-will-forward-you-the-OSUSEC-AWS-bill-never-gonna-give-you-up-never-gonna-let-you-down-never-gonna-run-around-and-desert-you-never-gonna-make-you-cry-never-gonna-say-goodbye-never-gonna-tell-a-lie-and-hurt-you-12345678'
```

All that is left is to run the script and we get our flag:

`osu{L0N6_W01f_H^x0r}`

Yay!!!
