# Any% WEB_THREE Writeup Speedrun

For the challenge, the main goal is to read from the flag.txt file on the server. Upon looking at the Dockerfile and the Flask source code, we can see from the Dockerfile that the flag.txt file is stored in the directory `/flag.txt` on the server from the Dockerfile. We can also see that the Flask source code checks the response from the server for `OSUSEC{`, and if it finds that string in the response then it is denied. This means that we cannot simply request to read the entire file because the response would contain the forbidden string and then we would be rejected. Hence, a simple directory traversal attack by manipulating the path of the file being rendered in the URL won't work as it would read the entire file to put in the response and get blocked.

We resort to server-side template injection or SSTI. The template engine that Flask uses is Jinja2, so we look up some Jinja2 SSTI payloads or writeups to assist us in getting to the flag. We find the following resource:

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2

In the Jinja2 section, there are a list of payloads for Reading Remote Files, which is exactly what we want. We just use one of the payloads and then change the location of the file that we want to read from to "/flag.txt" as indicated by the Dockerfile. Of course the problem of you putting the entire contents of the flag into the response and triggering the "check" for parts of the flag still remain, but unlike the directory traversal attack, here with SSTI we have control over the parts of the file that are read through the code used to actually read the file.

From testing, these two payloads work:
`{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}`
`{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}`

Since we have access to code that we can modify to change what gets rendered, we can make slight modifications to the payload so that when reading the file we only read the parts that don't contain `OSUSEC{` using string splicing on the string returned by read in order to bypass the check for the flag. This part is the brute force part where we need to splice the string a few times until we narrow down the range that contains the main flag. After trial and error, we narrow down the range of the splice to start at character 32 `[32:]`. The resulting payload is:

`{{ get_flashed_messages.__globals__.__builtins__.open("/flag.txt").read()[32:] }}`

The resulting main flag chunk is:
`{ok_s0_y0u_f1gur3d-out_d1rect0ry-tr@versal_w0nt-b3_helpful-here?}`

We can infer that the `OSUSEC{` part that is being checked for is the beginning part of the flag, so we prepend that onto the result of the splice to get the full flag.

`OSUSEC{ok_s0_y0u_f1gur3d-out_d1rect0ry-tr@versal_w0nt-b3_helpful-here?}`

Pretty quick challenge!

