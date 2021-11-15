# maldiant

## by *kaipan*

### Understanding The Problem

We are given a tarball that includes the encrypted image *flag.png.MALD* and the suspected malware PDF file *quarterly_report.pdf*. We also install the recommended tools *pyinstxtractor* and *python-uncompyle6*. The problem states that the malware attack was carried out by 'opening a PDF', which seems to indicate that the malware is an executable disguised as a PDF document, and by 'opening the PDF' we are actually executing the malware which takes the flag and encrypts it.

This hints that we should run the *pyinstxtractor* script on the *quarterly_report.pdf* file because the PDF a possible executable that we can get the contents of through the extractor. We run the script and the PDF does in fact contain .pyc files as part of an executable file, which confirms our suspicion that the document is secretly an executable. After extraction, a new folder is created with all the contents of the executable; we go into it to investigate. All of the files in this directory seem like they could come from a Python executable based on how they are named, with the exception of one .pyc file whose name stands out: *not_odysseus.pyc*.

We now take a closer look at the contents of the sussy file by utilizing the second tool: *python-uncompyle6*. We decompile *not_odysseus.pyc* and we get some very interesting Python code, which is shown below.

```python
# uncompyle6 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, Sep 28 2021, 16:10:42) 
# [GCC 9.3.0]
# Embedded file name: not_odysseus.py
from itertools import *
import os
if 'yes_please_remove_guardrail_friendo' not in os.environ.keys():
    print('GUARDRAIL TRIPPED: This is probably a good thing!!!!!!!')
    exit(1)

def encrypt_and_destroy(filename):
    try:
        with open(filename, 'rb') as (f):
            raw = f.read()
        magic_bytes = raw[:8]
        print(magic_bytes)
        enc = [a ^ b for a, b in zip(raw, cycle(magic_bytes))]
        with open(f"{filename}.MALD", 'wb+') as (enc_f):
            enc_f.write(bytes(enc))
        os.remove(filename)
    except FileNotFoundError:
        print('Bad file, please try again!')


encrypt_and_destroy('flag.png')
# okay decompiling ./not_odysseus.pyc
```

The *not_odysseus.pyc* file did turn out to be the malware portion of the executable. We can see the general algorithm used, where the *flag.png* file is opened, and its magic bytes are taken, then we encrypt the entire PNG image with the magic bytes, byte by byte, and whenever we get to the end of the magic bytes, we automatically cycle back to the beginning of the magic bytes to keep on XOR'ing each magic byte with a raw byte from the PNG image. We create a new encrypted file which is the original file name with a .MALD extension appended onto it and we write the encrypted bytes there before removing the original file itself.

In order to get back the PNG image, we simply need to undo the encryption steps. Rather than opening the *flag.png*, image to encrypt, we open the *flag.png.MALD* encrypted file to decrypt. We also realize that the original bytes were XOR'ed with the magic bytes of a PNG image, so in order to undo this XOR, we can just XOR the encrypted bytes with the magic bytes to get back the original bytes due to the property of XOR that allows XOR to inverse itself. All that remains is to set the `magic_bytes` variable to the byte string form of the magic number of a PNG image, and the script should be able to decrypt the file. We can optionally change the output filename back to a PNG instead of a MALD when we perform the write operation, but it doesn't really matter as the magic bytes determine the type of the file, not the extension that we see through the filesystem.

The last thing to note is the guardrail at the top of the script that prevents execution unless you have the specific environmental key `yes_please_remove_guardrail_friendo` set to 1 when you execute the script. This is presumably to prevent you from accidentally running the script and possibly damaging the contents of your computer. Since we are decrypting rather than maliciously encrypting, we can just get rid of this guardrail because decrypting is safe (we made the modifications to the script to decrypt, so we have control over the code). You could also just keep the guardrail, and set the key that it wants in the environment when you enter the command to execute the decrypt script, but that is just extra work.

We run the decrypt script, and our MALD file should be decrypted and it should have a different extension depending on whether you modified the filename and extension when writing the decrypted file or not. Regardless, we can see that this file is actually an image as their is an image preview thumbnail on Windows, which may also be there for other operating systems. We open the image and get the flag!

### Script

Here is the modified decompilation of *non_odysseus.pyc* that we use as a separate Python script named *decrypt.py* to decrypt the MALD file:

```python
# PNG MAGIC BYTES: 89 50 4E 47 0D 0A 1A 0A

# uncompyle6 version 3.8.0
# Python bytecode 3.8.0 (3413)
# Decompiled from: Python 3.8.10 (default, Sep 28 2021, 16:10:42) 
# [GCC 9.3.0]
# Embedded file name: not_odysseus.py
from itertools import *
import os
# if 'yes_please_remove_guardrail_friendo' not in os.environ.keys():
#     print('GUARDRAIL TRIPPED: This is probably a good thing!!!!!!!')
#     exit(1)

def encrypt_and_destroy(filename):
    try:
        with open(filename, 'rb') as (f):
            raw = f.read()
        magic_bytes = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
        print(magic_bytes)
        enc = [a ^ b for a, b in zip(raw, cycle(magic_bytes))]
        with open(f"{filename}.png", 'wb+') as (enc_f):
            enc_f.write(bytes(enc))
        os.remove(filename)
    except FileNotFoundError:
        print('Bad file, please try again!')


# Open MALD file to decrypt
encrypt_and_destroy('flag.png.MALD')
# okay decompiling ./not_odysseus.pyc
```

### Flag

`osu{M@G1C_ByT3S_AR3_N3At}`