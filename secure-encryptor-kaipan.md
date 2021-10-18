# secure-encryptor

## *by kaipan* 

### Decompilation

The decompilation of main has several important elements. We first see the random number generator being seeded, so we know that some element of randomness will be involved later. We also see calls to functions `get_otp` and `get_flag`. A quick analysis of both indicates that `get_otp` simply uses UNIX's pseudorandom number generator to generate an OTP or one-time-pad of 1024 characters while `get_flag` simply reads the flag file on the CTF server and stores it in a string to encrypt.

The first big function arrives: `random_pad`. We know that in one-time-pad the key must be longer than or the same length as the plaintext we want to encrypt,  Essentially, if the string passed to this function is shorter than the key, then we will automatically pad the string to match the length of the key. The padding is random; it uses the random number generator seeded earlier to randomly place the small string inside of a string that is the same length as the OTP, then it randomly fills the elements around the inserted string as a form of padding. We can get around this padding by using plaintext that is 1024 bytes, so there is no room for padding.

The last piece of the puzzle is the `encrypt` function. Ghidra doesn't quite decompile this right, as the first part of the function contains a loop when it should really be `memcpy`. We assume that the `memcpy` was to copy the passed string into a local buffer of 1024 bytes. The function then calls `memfrob` on the local buffer, which means that each character in the buffer is XOR'ed by the number 42. Then after that first XOR operation from `memfrob`, all the characters are XOR'ed again, this time with each corresponding character in the passed in OTP (through a for loop). Lastly, the padded flag ciphertext is encoded into base 64.

### Decrypting

The program then prints out the padded flag ciphertext to the user. Additionally, the program allows the user to enter his or her own plaintext and then the program will pad (if input < 1024 characters, otherwise it truncates if > 1024 characters) and encrypt the user's plaintext using the same OTP (thus it is not secure) and then display the ciphertext, with the plaintext going through the exact same process that the flag did. We want to avoid having padding, so we should be sending 1024 characters as input (which is only practical through a script). I believe this is called a **chosen plaintext** attack because the user can choose the plaintext and can then view the corresponding ciphertexts. Since we know exactly how the plaintext is encrypted from the decompilation, we can reverse the encryption. 

The general idea here is to first get the OTP from our chosen plaintext attack. We know that XOR operations can reverse a result as in `c = a XOR b` means that `a = c XOR b` (or `b XOR c` as XOR is commutative) and `b = c XOR a`. So in order to get back the OTP, we need to decode the resulting ciphertext from base 64 and use the properties of XOR just described. We need to undo the `memfrob` operation, and since XOR can undo itself, we just need to essentially `memfrob` the base 64 decoded ciphertext again. We can get any value back from XOR, so even though we don't know the OTP, since it is related to the plaintext and ciphertext through XOR, we can still recover it by XOR'ing the decoded non-memfrob ciphertext and the plaintext that we chose to get the OTP.

Now that we have the OTP, we can reverse the XOR encryption on the original padded flag ciphertext to get the plaintext with the flag. The padded flag ciphertext was encrypted the same way as our chosen plaintext, so we do the same steps: decode ciphertext from base 64, and XOR each character with 42 (what `memfrob` does) to undo the XOR done by `memfrob`. Now though, since we have the OTP and the final decoded non-memfrob ciphertext, we can XOR them together to recover the third related value from performing an XOR: the plaintext. The flag is definitely not 1024 bytes, so the plaintext is mostly padding, but a little searching will allow you to discover the flag.

### *pwntools* Script

```python
# Skeleton pwntools script
from base64 import b64decode,b64encode
from pwn import *

# Open connection
port = 4646
host = "chal.ctf-league.osusec.org"
conn = remote(host, port)

# Send & Receive commands
# Receives until pattern
print(conn.recvuntil(b"...\n"))

# Remove newlines within the ciphertext
a = conn.recvuntil(b"==").strip().replace(b'\n', b'')

conn.recvuntil(b"u: ")

# Chosen plaintext, we avoid padding by sending full 1024 bytes
conn.sendline(b"00"*1024)

conn.recvuntil(b"!\n")

# Remove newlines from ciphertext again
b = conn.recvuntil(b"==").strip().replace(b'\n', b'')

a=b64decode(a)
b=b64decode(b)


c = b"0"*1024
r = []

# De-memfrob and XOR plaintext w/ ciphertext to get OTP
for i ,item in enumerate(c):
    
    f = item ^ 42
    f = f ^ b[i]
    
    r.append(f)

g = []

# De-memfrob and XOR OTP with flag ciphertext to get padded flag plaintext
for i ,item in enumerate(a):
    f = item ^ r[i]
    f = f ^ 42
    f = f.to_bytes(1,"big")
    g.append(f)

print(b"".join(g))
```

### Flag

`osu{d0n7_u5e_4_1_71m3_p4d_m0r3_th4n_0nc3}`

