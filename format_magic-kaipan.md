# format_magic

## by *kaipan*

### Challenge Premise

This is a steganography/miscellaneous challenge. Basically we have stuff hidden inside of other stuff. The other stuff being an image in this case. We need to extract whatever is hidden in this image to get the flag in all likelihood.

### What's In The Image?

We run some general stego tools to find any sort of hidden files inside of the image. One such tool is **binwalk**. When you run it on the image, it states that it found the end of a compressed file, which indicates that there is some sort of zip or rar or tar file. We assume that it is a zip file since there probably is a different message for a tarball or other compressed file. We then look for the magic bytes for zip files. We found the magic bytes for an empty zip file, but since it is empty, it likely isn't right since there has to be some sort of content in the zip file, whether it be a flag or some other file.

Then we try to search for a non-empty zip file using its magic bytes using whatever tool we have at our disposal. We don't find the full magic byte sequence, but we do find 3 out of the 4 magic bytes for a non-empty zip file. At this point, you can use some sort of hex editor to change the first byte to match the first byte for a non-empty zip magic byte sequence. It works.

We can run **binwalk** again and it now detects the full zip file within the image. We use **binwalk ** again to extract the zip file starting at some address that is like *20D36* in the hex dump. We open up the zip file and see a QR code image, sweet! Unfortunately, we can't have nice things, since the zip is encrypted, so we can't view or extract the QR code without finding the password first.

### Hackerman Moment

Since the challenge doesn't really hint at any way of obtaining the password, we have to resort to brute forcing the password using tools like **John the Ripper** or in Lyell's case **fcrackzip**. We let the password cracker run over a premade list of passwords in the *SecLists* GitHub repo (more specifically, Lyell did [using the *10-ten_mil.txt* password list], and I freeloaded). The password ends up being `corrupted`. We can now extract the QR code and open it up, but the QR code looks quite lobotomized...

### QR Code Misery And Woes

The QR code looks like its missing its entire left half. We are given a resource on understanding how QR code works, and we can also find our own resources for extracting information from partial QR codes online as well. It turns out that QR codes have set patterns that make them readable by devices and all that. So we just need to recreate the missing pieces of the pattern so that the QR code tool that is given to us, Qrazybox, can parse the QR code. The biggest missing piece here are the finder patterns, which are the three squares that are in the corners of a QR code. We have one finder pattern already in the top right corner, but we are missing the same finder pattern squares and the whitespace around it for the top and bottom left corners.

We use whatever image editing tool we have on hand to add those finder patterns back in to the QR code. Now when we import the QR code image, Qrazybox is able to detect the image as a QR code (before it couldn't, stating that it only found one pattern, which we now know is the finder pattern). We use the tools menu to try to extract the data from the QR code, but we only get gibberish :(.

Turns out we need to recover the format string/pattern for the QR code as well, which determines what sort of masking is done on the QR code, which for simplicity's sake is needed to decode the QR code. We just brute force this on Qrazybox.

Observe the blue areas on Qrazybox, which is where the format pattern "bits" are supposed to be. We are missing bits for the top and bottom left finder patterns, but we have the partial finder pattern on the top right with its format pattern bits intact. We discover that Qrazybox lets us choose the format patterns when we click on the intact bits in the top right. Since we are smart (lmao), we know that we just need to choose the correct Error Correction Level and Mask Pattern until we get the same bits as the original bits in the top right corner. After trial and error, we find that the **L** error correction level along with mask pattern **3** produce the same bits. We save this setting, and Qrazybox automatically fills in the mask pattern for the top and bottom left finder patterns. That's lit.

Now we have everything we need to decode the QR code. We go to the tools menu and choose the Extract QR Information option to get our flag in the decoded data section at the bottom!

### Flag

`osu{c0rrup7ion_m4g1c}`