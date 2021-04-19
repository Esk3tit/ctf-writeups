# scrambled_noodles Any% Speedrun
### By kaipan	🇺🇸 PC	26m 51s	4/19/2020

In this challenge, we are provided with a .wav audio file. My first instinct was that this was going to be reminiscent of a stego challenge given the file type. There are a variety of ways to hide information in an audio file, like frequency modulation, and encoding the hidden information in the least significant bits of the audio file. It took a bit of research and trial and error to find and test all the different ways to hide information in an audio file. In the case of this challenge, the hidden information is stored in the **spectrogram** of the audio file, which are "a visual representation of the spectrum of frequencies of a signal as it varies with time". Simply put, spectrograms are pictures of sound and visualizing what sound would "look" like.

Using a spectrogram visualizer/generator on the .wav audio file, we get a link to a pastebin...

`https://pastebin.com/1dsgDa6C`

The pastebin contains the following information:

> Case 20210410-001 Update: 4/16/2021
> 
> Haha, I made you solve a stego chall to get an update on this case!
> Happy late April fools!
> 
> I've looked into that WLAN hotspot thing and I think I've got a lead.
> It's a guy who goes by "Barron Benedict Jr. III", an alleged resident
> of Ascension island... I've seen him use online username
> "TwoBoatsMan2", but apart from that, I have no further progress, I've
> been addicted to this game AmongUs...

The first thing we do is track down the username "TwoBoatsMan2" online, and we find a twitter account that matches the username and actual name of "Barron Benedict Jr. III".

In one of the pictures, it shows his web browser with his reddit user name of  `u/ascension-wlan`. We navigate to his reddit posts, and we find a post where he has another picture of his browser, but his network properties window is also on display, showing all of his information...

We want to find the hotspot that the subject has created, so we can use his network information in the public space to do just that.

Using the OSINT framework, we do a little bit of experimenting to find the proper tool to let us find hotspots based one of the network properties. The network property we use is the MAC/physical address which is `70-70-8B-69-45-FC`. The tool we ended up using was WiGLE. Unfortunately, you need to create an account to search for a network address, and I didn't want to create another account that I might not use ever again, so I delegated the task to my teammates. They made the account and searched for the MAC/physical address. We looked on the network map to find the location in the middle of nowhere (presumably so that anybody else who uses the service legitimately won't run into the flag), and that location has the flag as its marker name.

`OSU{OSINT_aint_that_hard}`

Not bad for a scavenger hunt I suppose.
