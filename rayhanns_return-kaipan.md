# Rayhann's Return Any% Speedrun
## Kai Pan 🇺🇸
---
**Extracting The Files**

The challenge begins by having us download a tar file *CTG-2020-10-0001.tar.gz*, which we can immediately extract to get at its contents:
1. CTG-2021-02-19-001.iso
2. CTG_STANDARD_WORDLIST.txt
3. CTG-2021-02-19-40972240-MEMO.pdf

The memo is pretty sick and it tells us that we need to get the flag by accessing an AWS server and reading the flag from there, but the important items are the .iso file and the word list .txt file. We can mount the .iso image to access its contents, or we can extract it as well.

I extracted it, and the only notable items were a Journal file and a rhodgson.kbdx file. It turns out that the .kbdx file is a password database file. We assume that the password database would contain the login credentials to the AWS server that hosted the flag, but the problem is that we need a master password in order access the password database. In order to find the master password, we use a tool called john (john-the-ripper). We need to install it first/build it from source before starting the next step.

---
**John Lowkey Kinda Confusing**
First, we need to convert the .kbdx file to a hash file that john can then work its magic on to find the master password. We do this by running john's keepass2john tool on the .kbdx file and then redirecting the output to a new file which is the hash file. We run the following command (note that keepass2john should be the path of the keepass2john tool which depends on where you built the john the ripper suite of tools from source)

`keepass2john rhodgson.kbdx > hash.txt`

We can view the hash.txt file but it's mostly gibberish save for a few keywords like keepass and the name of the database.
Now that we have a hash file, we can run the main john tool on it to get the master password. If you recall from earlier, we had a word list text file in the tar; we can use this word list to speed up the password cracking because word list is simply a list of possible passwords, and if it is given to us, then it is reasonable to assume that the master password is in the word list. We run the following command to get the password (note that john needs to be a path to the john tool once again):

`john hash.txt --wordlist=CTG_STANDARD_WORDLIST.txt`

the password to the database is *1hodgson*. We can use the Keepass application to open the database file and enter the master password to gain access, but one of my partners introduced me to the commandline interface version of Keepass called kpcli.
I used the open command on the rhodgson.kbdx file and entered in the password. I gained access to the database and I dug around. Turns out that there is an entry in the database called *My Flag Box*. We view this entry with the show command, and we get the URL/address to the AWS server, a username on the server, and the password to said account.

- Username: ubuntu
- Password: As.3S;d0cvAS3kmm3VI(N
- URL: 34.216.68.186

---
**Homestretch: Connecting to the AWS server for the flag**
We do make note of the note at the bottom of the entry, stating that this Rayhann guy screwed up the flag by messing with the SUID. We then ssh to the server at the URL with the username and password provided. We can see the flag file, but uh oh! The flag is owned by root, and we are not root, so we can't access the file directly! We decide to investigate the .bash_history file to see what could've possibly happened to the flag, and we come across the line where the ownership of the .flag file was changed to root with the chown command, but more importantly, we discover that above it, Rayhann apparently sudo chmodded vim with the u+s mode, meaning that the SetUID bit (the s mode) enforced user ownership on an executable which is vim in this case. So that when vim is ran, vim executes with the owner's permissions/user ID, not the permissions/user ID of the person who executed it. Since vim is owned by root, when vim is run it runs with the owner's UID, meaning that vim runs under the root User ID. Therefore, we can use vim to access the .flag file, with the user ID of root, under the user ID of root. We simply open the .flag file with vim which now runs under the root User ID (instead of the User ID of person that is running it, which is us: ubuntu). The flag is:

`osu{rAyh44n_isb4d@_0ps3c}`

Esketit fellas!
