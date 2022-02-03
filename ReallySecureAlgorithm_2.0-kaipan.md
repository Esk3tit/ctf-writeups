# ReallySecureAlgorithm_2.0

## by *kaipan*

### Description

We have a modified RSA client and server. The client connects to the server and receives the encrypted message. We have access to the server source code, so we can see that the message gives us the flag ciphertext, the number of bits of the key (hardcoded to be 2048), the integer *e* which is hardcoded as 65537, and the value of N which is the product of the two primes *p* and *q* that are "randomly" chosen as part of the RSA algorithm for encryption and decryption. We need to find a way to decrypt the ciphertext and get the flag given these 4 pieces of information from the server.

### Exploit

The code that does the RSA 2.0 encryption on the server is actually pretty straightforward and follows the official RSA algorithm except for one part that we can use to exploit to break the RSA encryption relatively easily. We read through the source code and lo and behold! The server has a decryption functionality! Since we can get the data from the server by running the **client.py** script as per the instructions of the challenge, we can then plug in the data into our own script and use this decryption function and the data the server gives back to decrypt the returned ciphertext in our own script by plagiarizing the server code (bless up for server source code, made it way easier haha) and modifying it to fit our needs.

The decryption function is as follows:

```python
# Decrypt a given int ciphertext
def decrypt(self, ctxt):
	bytes_ptxt = pow(ctxt, self.d, self.N).to_bytes(self.n_bits//8, "big")
	ptxt = str(unpad(bytes_ptxt, self.n_bits//8), "utf-8")
	return ptxt
```

We need to work backwards to understand what we need to do for decryption. We can see that we just compute an exponent, then we remove padding from the bytes and convert to string to get back the original plaintext. There is only one obstacle in our way; all the values that are used in this function is either returned to us from the server, or are hardcoded values in the server source code that we can just use directly,  EXCEPT for *d* (decryption exponent). This means that we must calculate *d* ourselves, but how do we do that?

We now turn our attention to an earlier part of the server source code:

```python
# Get two n_bits length primes and compute public modulus
p = getrandbits(self.n_bits)
while True:
	if isPrime(p):
		break
	p += 1
q = p + 1
while True:
	if isPrime(q):
		break
	q += 1
self.N = p*q

# Compute keys
carmichael_N = int((p-1)*(q-1)//GCD(p-1, q-1))
self.e = 65537
self.d = pow(self.e, -1, carmichael_N)
```

We can see that *d* is calculated as the modular multiplicative inverse of *e* modulo Carmichael's totient. The value *e* is hardcoded so we don't need to worry about it, but the Carmichael's totient is calculated using *p* and *q*, the two prime numbers that should be randomly chosen with similar magnitudes but differ in length by a few digits (makes factoring harder, and expensive factoring makes it hard to break RSA which makes it pretty secure normally since multiplying primes is easy for generating keys, but to reverse this operation and break RSA it is a lot harder when you need to factor the right numbers that were multiplied to generate the key). I say should be because that is not what RSA 2.0 does; if you look at the top of the previous code snippet, we can see how *p* and *q* are generated. The value *p* is presumably random because we obtain it by calling `getrandbits` and passing `n_bits` which essentially is hardcoded to 2048. So *p* is a random number, and then we run a loop to find the nearest higher prime number starting at *p*; if *p* is a prime, we break the loop and are done, otherwise we increment *p* and check if it is a prime. We just increment *p* until *p* becomes prime.

We notice that *q* is calculated in much the same way, except rather than having *q* start out as a random number like *p* by *q* to the result of `getrandbits`, the code has *q* start out as *p* + 1 where *p* at this point is already a prime number. We then increment *q* by 1 until *q* becomes a prime number. Technically in this sense, *q* is not random since it depends on the value of *p*. More specifically, since *q* starts at *p* + 1 and gets incremented until we find a prime, *q* is just the next prime after *p*, meaning that we break the security rule where both *p* and *q* need to be random primes, since if we know *p* we can just find the next prime and calculate *q* which is not secure. This weakness is how we're going exploit the RSA 2.0 algorithm to find *d* and decrypt the ciphertext.

We know that *p* and *q* are basically consecutive primes. This means that we can just take the square root of *N*, the product of *p* and *q* to get a number between *p* and *q*. The way I rationalize how this works is that since the numbers are relatively close together magnitude wise, when you multiply them, it is like you are multiplying a number with itself (of course *p* and *q* are large numbers, so the difference in their values is pretty large, but this abstraction still applies), which is basically squaring one of the numbers. We can get a clearer picture of this with an example, say we multiply 2 and 2.1. We get 4.2, which is pretty close to the square of 2, which is 4. Thus to undo the "approximate squaring operation" of *p* * *q* (this is *N*), which is approximately *p* * *p*, we simply square root the result of *p* * *q*, N. Going back to our 2 * 2.1 example, square rooting the result (4.2) gives us 2.04939015319, which is between 2 and 2.1. Similarly, we can extrapolate that when we square root *N*, we get a number that is between *p* and *q*. Since we know that *p* and *q* are **consecutive primes** and the number we just got is between *p* and *q*, we can find *p*, the lower bound prime, by decrementing the root of N until we find a prime number, and inversely, we can find *q* by once again incrementing the root until we find a prime number (the root is in between the primes, so we "travel" in both directions to find *p* and *q*).

At this point the challenge is pretty easy, since the server source code gives you the code you need to calculate *d*, and then it also gives you the decryption function as well. We just plagiarize these functions for our own script, and then pass in the values that were given to us by the server. We just run the script to calculate *d*, and then we use the *d* value in the decryption function with our server data to get the flag!

### Script

One thing to note here, is that *N* is big number. Python's `pow` function from the `math` library no like big number, so we have to actually make a custom script/function to calculate the square root that works on large numbers. I being the genius that I am plagiarized this function from StackOverflow like a true gamer. You can see the script below:

```python
def nth_root(x, n):
    # Start with some reasonable bounds around the nth root.
    upper_bound = 1
    while upper_bound ** n <= x:
        upper_bound *= 2
    lower_bound = upper_bound // 2
    # Keep searching for a better result as long as the bounds make sense.
    while lower_bound < upper_bound:
        mid = (lower_bound + upper_bound) // 2
        mid_nth = mid ** n
        if lower_bound < mid and mid_nth < x:
            lower_bound = mid
        elif upper_bound > mid and mid_nth > x:
            upper_bound = mid
        else:
            # Found perfect nth root.
            return mid
    return mid + 1

root = nth_root(514973057526651648113929673225369150620304074345192765294093014941581587530035114930755524053316899009647379771775625230368859338665100151851375663738184901053670600718309101877279369526258018035806059767667578370273832207316757160636844445186672177617484121593580371420995831268166094985702755240596895352765935087121277204351859523688154280322760189558095903608973696055590952744662140210105645878873849799861639529634407621730239495844094051142363190260117692282440587224014914716454771990110817953197010390388369941312859621181140661287301392635875241543024208933184235282533453762899383166995755447198371865236804220512674262997578078218091829573272175532700978388790836986712561352872517397941937842814923836009015205551685858680627780381912313406102204474509169956418518961830125364343854990782025202486486680676603448988495203824993378535509108580544335466794846979344413345089390256502047254418538794982404829458136390876775443228533683739054346932335584904928249105684854663230232544480210488642809000386032232794101342728163445567995804070411915489644134250713028804268618375785724704544760979798550331791119500106069485157532282266811352436971998619649212468536256319772090296489336031033032293735724325635709955557424311, 2)
print(root)
```

Then once we run this script on the *N* we get from the server, we can just use that value in our script that calculates *d* and then decrypts the ciphertext, which is shown below. We must provide the given values that are hardcoded in the server source code as well as the values returned by the server with the ciphertext. We implement the idea described in the **Exploit** section in this script.

NOTE: This code requires the `pycryptodome` library to function.

```python
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import GCD, isPrime

# The square root of N
n = 22693017814443535312992042003503849229301926050262564154300925732446458973226715745193963081314480234837545570748062954561479872316017760090026520691292028497149367314753016221539300745290305655390224838517472191334004463280800900721895123648485128593839011180083548510922845562863893122065150261221343678063619193140955959934506577948210446202297994275179904822109258707914302021864272845653934647540273782977816620356494328597773338737201409555057483845011146177663964707210826262181916337357762751606038443097831700959012092247966692168357239352144708749618415027445736904824595252257280894050134208401625169239343

def nearest_upper_prime(q):
    while True:
        if isPrime(q):
            break
        q += 1

    return q

def nearest_lower_prime(p):
    while True:
        if isPrime(p):
            break
        p -= 1

    return p

# Finding consecutive prime from root of N in both directions
p = nearest_lower_prime(n)
q = nearest_upper_prime(n)

e = 65537

print(f"p: {p}")
print(f"q: {q}")

# Calculate d
carmichael_N = int((p-1)*(q-1)//GCD(p-1, q-1))
d = pow(e, -1, carmichael_N)

print(f"d: {d}")

cipher = 322481726876600523254912119302041975983508963118826898178382259528355485998007548932716063743873289362678516682978904018731743613263213408111436775802986791810771390117853878657963669879802039985613928461144297589529410943325221665548301758068641809411879137824583892915611300154758723280739383267560059155211773978264055933992338567732065615170668699078286977390332730986284532811234388730717410733547579961381992828103387495306946516339840547062618620709573628144234859396398058167351432282978750409910225504465762482174931839111515323392538648701149798466051651688497618699556733679008746760406165523552485990095333488760620011423269023028817484156791250510065390580985163832448140132115718850675883052073608937762515972197115364523595578089715643068454832040423112963266622734831357304613553528981938327829928957436757992166465371333211730239495449567046790542391857131088621069651270376851921580793527032370620396369955011686477242750299465776743187946587417917721028713914560237566516413750685597877837994027740581396346193579183052178576515517856690257655826810497760460308571871598961395283244308929518643059162656713829414105354183135181240562611160311851909016321010070789051422527245345462202807175088461933681445715241134

N = 514973057526651648113929673225369150620304074345192765294093014941581587530035114930755524053316899009647379771775625230368859338665100151851375663738184901053670600718309101877279369526258018035806059767667578370273832207316757160636844445186672177617484121593580371420995831268166094985702755240596895352765935087121277204351859523688154280322760189558095903608973696055590952744662140210105645878873849799861639529634407621730239495844094051142363190260117692282440587224014914716454771990110817953197010390388369941312859621181140661287301392635875241543024208933184235282533453762899383166995755447198371865236804220512674262997578078218091829573272175532700978388790836986712561352872517397941937842814923836009015205551685858680627780381912313406102204474509169956418518961830125364343854990782025202486486680676603448988495203824993378535509108580544335466794846979344413345089390256502047254418538794982404829458136390876775443228533683739054346932335584904928249105684854663230232544480210488642809000386032232794101342728163445567995804070411915489644134250713028804268618375785724704544760979798550331791119500106069485157532282266811352436971998619649212468536256319772090296489336031033032293735724325635709955557424311

# Decrypt
def decrypt(ctxt):
    bytes_ptxt = pow(ctxt, d, N).to_bytes(2048//8, "big")
    ptxt = str(unpad(bytes_ptxt, 2048//8), "utf-8")
    return ptxt

print(decrypt(cipher))
```

### Flag

`osu{d0n7_ch0O5e_pR1m3s_7h4t_R_5imIl4r}`

The lesson here is to choose truly random primes for RSA :).