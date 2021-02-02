## Any% Snowcone Writeup Speedrun

Objectives:

 1. Find/recover the encrypted files
 2. Decrypt the encrypted files 

***Find the files***
This first part involves Wireshark. This was my first time using Wireshark, but with the help of my group I managed to simplify the process as follows: we first follow the TCP stream of the first entry to get a general idea of what happened. The most important parts are highlighted in red by Wireshark. First, a file named snowcone.exe was downloaded using the curl command. Then the snowcone.exe file was run on *super_sensitive_documents*. Then the output was turned into *exfil.zip* with the tar command. Finally, the zip file was encoded in base 64 resulting in the final file *exfil.zip.b64*.

We simply need to reverse these processes to get the documents that were lost. We start by copying the certificate text into a file called *exfil.zip.b64*. We then decode from base 64 using the **decode** command on the terminal or use an online decoder like I did. We should get the decoded exfil zip file which we can unzip using commands on the terminal or whatever to get the encrypted documents. This completes the first step of recovering the files.

***Unransomware the files*** 
Rather than pay hackers hundreds of dollars in bitcoin to decrypt the files for you (if they even keep their word), why not just reverse engineer the encryption and do it yourself for free?
This is where DnsPy comes in. We can open up the snowcone executable with DnsPy to decompile it in a sense and view the source code. We trace through the program to find out how it works.
Looking at the main function, we can see that it calls a method named `MakeItSnow`. We find the function and see the following code:

```vbnet
public  static  void  MakeItSnow(string  dir)  
{  
	string[]  array  =  Directory.GetFiles(dir);  
	for  (int  i  =  0;  i  <  array.Length;  i++)  
	{  
		SnowMachine.SmallSnowcone(array[i]);  
	}  
	array  =  Directory.GetDirectories(dir);  
	for  (int  i  =  0;  i  <  array.Length;  i++)  
	{  
		SnowMachine.MakeItSnow(array[i]);  
	}  
}
```

The important function is `SmallSnowcone`, and the code is as follows:

```vbnet
if  (path.EndsWith(".sn0w"))  
{  
return;  
}  
using  (FileStream  fileStream  =  new  FileStream(path,  FileMode.Open,  FileAccess.Read))  
{  
using  (FileStream  fileStream2  =  new  FileStream(path  +  ".sn0w",  FileMode.Create,  FileAccess.Write))  
{  
byte[]  array  =  new  byte[fileStream.Length];  
byte[]  array2  =  new  byte[fileStream.Length];  
fileStream.Read(array,  0,  (int)fileStream.Length);  
string  text  =  SnowMachine.PickSomeFlavoring();  
SnowMachine.SaltBaeDatFlavorIn(array,  array2,  text);  
byte[]  array3  =  SnowMachine.OTP(Encoding.ASCII.GetBytes(text));  
for  (int  i  =  0;  i  <  32;  i++)  
{  
fileStream2.WriteByte(Convert.ToByte((int)(array3[i]  |  128)));  
}  
fileStream2.Write(array2,  0,  array2.Length);  
}  
}  
File.Delete(path);
```

This is where the encryption happens, observation shows that several functions are called in the encryption process, namely `PickSomeFlavoring`, `SaltBaeDatFlavorIn`, and `OTP`. Let's find out what each is doing!

**PickSomeFlavoring()**
```vbnet
string  text  =  "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";  
string  text2  =  "";  
using  (RNGCryptoServiceProvider  rngcryptoServiceProvider  =  new  RNGCryptoServiceProvider())  
{  
for  (int  i  =  0;  i  <  32;  i++)  
{  
byte[]  array  =  new  byte[1];  
rngcryptoServiceProvider.GetBytes(array);  
text2  +=  text[(int)array[0]  %  text.Length].ToString();  
}  
}  
return  text2;
```
Breaking down the code, we essentially have a random number generator that randomly selects characters from the `text` string and makes a password of sorts that is 32 characters long and stores it in `text2` before returning `text2`.

**SaltBaeDatFlavorIn()**
```vbnet
for  (int  i  =  0;  i  <  file.Length;  i++)  
{  
snow[i]  =  Convert.ToByte((int)((char)file[i]  ^  flavor[i  %  32]));  
}
```
This function essentially converts the data in the original file to the encrypted data using the xor operation and some fancy modulo wrap around on the flavor string from the prior function.

**OTP()**
```vbnet
byte[]  array  =  new  byte[input.Length];  
for  (int  i  =  0;  i  <  input.Length;  i++)  
{  
array[i]  =  Convert.ToByte((int)(input[i]  ^  66));  
}  
return  array;
```

This function just xors the input with decimal 66 and returns the new byte array.

The last part of the main encryption function has this snippet of code which we should also be aware of:
```vbnet
for  (int  i  =  0;  i  <  32;  i++)  
{  
fileStream2.WriteByte(Convert.ToByte((int)(array3[i]  |  128)));  
}  
fileStream2.Write(array2,  0,  array2.Length);
```
This sets the high bit on the array that we OTP'ed and writes those 32 chracters to the file FIRST before writing the actual encrypted contents of the original file.

Now we simply reverse these changes with our own script. Here's how I did mine in Python:

```python
f = open("super_sensitive_documents/flag.txt.sn0w", "rb")
highbit = bytearray(f.read(32))
for i in range(32):
    highbit[i] = highbit[i] ^ 128
def reverseOTP(input):
    array = []
    for i in range(len(input)):
        array.append(input[i] ^ 66)
    return array
def reverseSalt(file, snow, flavor):
    for i in range(len(file)):
        snow[i] = file[i] ^ flavor[i % 32]
undoneOTP = reverseOTP(highbit)
file = bytearray(f.read())
snow = bytearray(len(file))
reverseSalt(file, snow, undoneOTP)
o = open("flag.txt", "wb")
o.write(snow)
f.close()
o.close()
```

Stepping through the script, we first read the first 32 characters of the encrypted files, which are the ones with their high bits set. We loop through each of those characters and reverse the high bit set with XOR. Then we have definitions for the functions that reverse the OTP and the salt, since those operations use XOR, we can simply do the same XOR operation again on the encrypted data to reverse it. We pass in the original high bit string into our `reverseOTP` function to get the password that was generated from `PickSomeFlavoring` in the snowcone executable. Lastly, we read the rest of the file, which is the encrypted content and make some byte arrays for the `reverseSalt` function. We pass in the password that we decrypted along with the two byte arrays to decrypt the entirety of the file. All that's left is to write the results to a file and we can get our flag (and we can do the same for the other encrypted files to see what's up, nice pictures btw).

**Flag**
`osu{1f_it_d03snT_5now_1m_GoNn4_sue_sOm3b0dy}`

We did it boys, ransomware is no more!








