# deprecated_echo

## by *kaipan*

### Steganography

The first part of this challenge is steganography. We are provided with an image that contains hidden data and information that mentions the number of bits relating to the image is 3. A link to a least significant byte steganography decoder is provided (created by OSUSEC club members by the way!!!). Using the tool is pretty simple provided you cloned the repository and have the Pillow pre-requisite installed. We run a simple decode command and provide the encoded image, then the number of rightmost bits to use (which was given to us in the challenge description where bits = 3), and the output file which we just give an arbitrary name to and make sure it is a JPG image. Decoding the image successfully should give us a new image that has a pastebin link at the top left corner: https://pastebin.com/9bRN2Eah.

### Python `input` Vulnerability

The pastebin gives us the following source code for the script running on the challenge server:

```python
#!/usr/bin/env python2

if __name__ == '__main__':

    try:
        # Get User Input and file  as Strings
        user_input = raw_input("Enter a string:")
        user_file = raw_input("Enter a location in the current directory:")

        # Check Directory
        if ['.', '/'] in user_file:
            raise ValueError("Bruh")

        # Write user input to a file
        if user_input.isalpha():
            f = open(user_file, 'w')
            f.write(user_input)
            f.close()

        # Return the input to the user
        print user_input

    # Catch-all for exceptions
    except Exception as exc:
        print "Whoops, something happened :("

        # Dump the exception to somewhere
        file_location = input("Where should I dump crash log to?:")
        
        # Check file path is valid
        if ['.', '/'] in user_file:
            f = open(file_location, 'w')
            f.write(str(exc))
            f.close()
```

The important thing to notice here is the usage of the function `raw_input` and `input`. Python 2's `raw_input` is equivalent to Python 3's `input` function (Python 3 gets rid of Python 2's `input` function and renames `raw_input` to `input`). `input` in Python 2 parses the user input by the input's intrinsic type and doesn't change the typing of the input when it is parsed (ex. entering an integer for the `input` function parses that input as an *int* type variable) while `raw_input` parses all inputs to a string variable. Another way to think of it is that `input` is like running the `eval` function to evaluate expressions in string format on the string variable/data returned by thee `raw_input` function. As such, converting to string data with `raw_input` is far more safe because every input is treated the same way, whereas `input` introduces some complexity by evaluating the user input, and it should come as no surprise that Python 2's `input` functions have vulnerabilities that can be exploited to read the flag. The common vulnerabilities that you find upon doing research would be the fact that if you provide `input` with a variable name that is present in your source code, then it would get evaluated to the value of the actual variable in your code. So if your code has a variable that holds a special value that is then compared against your user input, the user could enter the name of that special variable into `input` and it would get evaluated to the value of that variable, such that if you were comparing for equality between the input variable and the special variable, the input variable gets evaluated to the special variable, and it follows that the special variable is always equal to itself. Similarly, if you provide a function name like you would for a function call (with parentheses) then the input would get evaluated and the function would get called.

We can actually exploit this last fact. There is a built in function called `execfile` that can be used to read the flag. `execfile` is normally supposed to parse a file and run the code within the file, but if we tell `execfile` to run the *flag.txt* file then it will try to run the flag contents, which isn't actually code, so it will crash, but the error message leaks the contents of the flag (the error points to where the problem is, so it prints out the flag because it can't parse the flag to indicate to the user where the error occurred). We first need to get into the `except` block in the source code, which you can do by entering a '.' or '/' character when it asks you for a location in the current directory (as indicated by the source code). Then when it asks for the location to put the crash log, which uses the vulnerable `input` function, we tell it to run `execfile` on the flag file through the input **execfile('flag.txt')**. The program will error and leak the flag as part of the error message alerting the user to the specific spot where the error occurred.

Another approach is to use the built in `__import__` function. This can import modules just like the `import` statements we normally use. We can use third party or external modules to leak the flag. One way we can do this for example is to reverse a shell and gain access to a shell on the server. That way we can run **cat flag.txt** and easily get the flag. We can do this by using the *os* module's `system`, which executes a command provided as a string in a subshell (it calls the C language's `system` function as well, so they both behave the same way). We can tell the subshell to spawn a complete shell for us to complete our reverse shell. We can use the following input when we reach the `input` function: `__import__('os').system('/bin/sh')`. This spawns an sh shell on the server that we can freely use to get the flag.

### Flag

`osu{m1sc_CTF_b35t_cTF}`