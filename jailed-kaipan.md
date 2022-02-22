# jailed

## by *kaipan*

### Description

As the name implies, the Python jail that you are "locked in" prevents you from performing certain actions by rigorously validating your user input, giving you no freedom just like being locked in a real jail. We are tasked with bypassing all of the restrictive measures imposed on us to "escape" and get the flag. There is no file for this challenge, so there is no source code. We are given a server connection and we need to manually understand what the jail script is doing (or use a library to give you source code if you can figure out the way to import and call it, which trivializes the challenge).

### Maximum Pain At The Beginning

Before we ended up cheesing the challenge and speedrunning it, figuring out what the script actually did manually by testing user inputs was pretty painful. The script restricts character input, so we had to just test it by keyboard mashing the entire keyset to see what characters were usable (the non-usable ones were echoed back with a "Denied" message). It turns out that the script also can execute Python code. Calling functions like `print` worked as long as you didn't use any restricted characters. The next big discoveries were the ability to use the `eval` function to potentially execute any code we wanted, and the fact that the "command prompt" of `a = ` actually means what it means programmatically (a variable `a` is assigned the value on the right hand side of the = sign, which is the area that we type in, thus we can assign values to the variable `a` and then reference it within the code we write as input).

Now we have all of the important stuff to get started, but the character filter is very annoying. Is there a way for us to bypass the character filter, perhaps by exploiting the fact that values can be saved to the variable `a`? Of course there is! We can use the `input` function to enter whatever characters and thus whatever code we like. The user input to `input` is not validated, so anything goes, and the result gets saved to the variable `a`. If you factor in the command prompt, it should read exactly like Python and do what you expect: `a = input()`; we tell the script to run `input`, and the script automatically saves our user input to the variable `a` as indicated/hinted at by the "prompt" of the script. So now we can enter any code in for user input, and then execute it with `eval` by passing in the variable `a` as an argument since `eval` is not banned... Arbitrary Code Execution! But at what cost? The answer is maximum pain from having no idea what to do since we had nothing really to work off of at the start, and having to figure all of it out.

### Top 1 Accidental Skip Discoveries In Speedrunning *jailed* (NOT CLICKBAIT)

Well it turns out that there is a way to completely cheese the challenge that the group discovered by accident through running the right code at the right time. Knowing that we can store code as user input and then execute it with `eval`, we first did what anybody would do. We called the `DATA` function that the script told us existed when we made the connection to the server! Keep in mind that we had no idea what the source code of the `DATA` function was when we started, so once again, we had to sort of just trial-and-error reverse engineer/figure out what the function was doing. The function asked us to input data to decode, and you gotta be on something if you believed even for a second that we didn't immediately try to decode the flag. We all entered what we thought the flag would be: "flag", "flag.txt", and all that other jazz. Of course, we all got various errors, but mostly "invalid load key" errors, indicating that the user input was actually being decoded, and we needed to pass in some sort of encoded input (most likely base64 based on our intuition). Little did we know that the errors were one of the few events that had to lineup for our cheese discovery to work.

Upon getting the error, we get kicked back to the original prompt. It was at this point that we were given the hint to use the `inspect` library, which led us to try to use an import to load the library. We ended up using the `__import__()` function to import `inspect`. This suggestion too, is part of the events that needed to line up. We used the `getsource` function to get the source code from the `inspect` library (pass in function as argument to get source code of: `__import__("inspect").getsource(DATA)`). The source code for `DATA` is as follows:

```python
def DATA():
    make_insecure()
    user_input = input("What data do you want to decode?\n")
    decoded = base64.urlsafe_b64decode(user_input)
    out = []
    for byte in decoded:
        out.append(memfrob_byte(byte))
    safe_data = bytes(out)
    print(pickle.loads(safe_data))
    make_secure()
```

We can then use `getsource` to view the other functions like `make_insecure` and `make_secure`, which are also shown below:

```python
def make_insecure():
    global original
    __builtins__.__dict__.clear()
    for func in original:
        __builtins__.__dict__[func] = original[func]
```

```python
def make_secure():
    global original
    original = __builtins__.__dict__.copy()
    __builtins__.__dict__.clear()
    safe_builtins = [
        "help",
        "input",
        "any",
        "print",
        "all",
        "Exception",
        "exec",
        "eval",
        "isinstance",
        "str",
        "bytes",
    ]
    for func in safe_builtins:
        __builtins__.__dict__[func] = original[func]
```

Apparently we weren't supposed to be able to execute `__import__`, as mentioned by our coach (the suggestion/hint given earlier brought us to this point so it had to line up in this order of events), but we were able to execute it (we didn't know how at this point). Of course, since we could execute seemingly illegal code, we went straight for opening the flag and reading it by storing the following code snippet in `a` and then executing it with `eval`: `open('flag','r').read()`. We got the flag, but not first blood **:(**.

### How The Speedrun Strat Actually Works

We were really confused on how we got the flag, since if our connection to the server was lost, we couldn't immediately use `__import__` when we reconnected as we get a "not defined" error. It turns out that we could only call `__import__` after calling `make_insecure` as the creator of the challenge enlightened us, which in hindsight makes sense, since if you look at the source code for `make_insecure` it seems to give you all the power by giving you access to all of the symbols of the script (it gets the global symbols, and essentially assigns all of the global symbols to the built-in object, giving us access to all of the globally available symbols of the script that is running, which more than likely has a symbol for the import function, which is why we can call `__import__` after calling `make_insecure` as we now have access to import functionality in the built-in which I guess has all the stuff that the user can actually use or something like a local symbol thingy or whatever I don't really know what I'm talking about haha) including `import` which lets us use it afterwards in our code that we can execute through the script.

Now the question is: how did we call `make_insecure` if we had no idea what the source code was until we called `getsource` from the `inspect` library which needed us to use `__import__`, which is banned to begin with? Well, if you look at the source code for `DATA`, we can see that the first thing the function does is call `make_insecure`, and we tried calling `DATA` the first thing after figuring out that we could arbitrarily execute code as mentioned earlier. So we got access to all the global symbols which let us call `__import__` as a consequence (and it also why some people who disconnected and/or didn't call `DATA` upon reconnection if they got disconnected got a not defined error). We can also see that there is a call to `make_secure` at the end of the `DATA` function, and analysis of the source code shows us that this function restricts the available symbols in our built-in. Remember how I foreshadowed the error earlier? Well that error occurs during user input, which happens **AFTER** `DATA` calls `make_insecure` to give us all the power but boots us back to the "command prompt" **BEFORE** `DATA` gets a chance to call `make_secure` to restrict our built-in symbols again. So by crashing `DATA` when it asks for user input, we were able to implicitly call `make_unsecure` (and no `make_secure` call is made to reverse the changes since `DATA` crashed before it could be called) and therefore gain access to global symbols that presumably let us call `__import__` and `open` and `read` to read the flag.

If you really wanted to speedrun this challenge, simply connect, store the call to `DATA` and then execute it with `eval` (or `make_insecure` if you had the powers of hindsight which lets you skip the next step), then crash the input that `DATA` asks you to enter. Then at this point you can store the code for opening and reading the flag in `a` and then just `eval` the variable `a` to get the flag.

### Flag

`osu{n3v3R_unp1ckL3_Untru5t3d_Us3R_data!}`