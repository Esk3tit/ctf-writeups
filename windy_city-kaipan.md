# windy_city

## by *kaipan*

### Description

This is a geospatial OSINT challenge. We are basically given a picture, and then we need to find the location in the picture which relates to the flag. In this case, we are given a picture of a building, and the flag is the name of the artist who painted a mural on the left side of the depicted building. So we need to find the location of the building from the image, and then use Google Map's street view to navigate around the building to see the mural. Then we need to find the mural artist's name which is the flag.

### Reverse Image Search

The main way we are going to find the location of the building in the image is by reverse image searching the image or parts of the image. This should give us information on the image by finding where the image is used on the internet, thus giving us context to further track down the physical location of the building in the image (the sites that use the image likely have information on where the image was taken and/or what is in the image which helps us find where the building in the image is).

In order to make the reverse image search process easier, we use an extension called *Search by Image*, which lets us easily search on multiple image search engines for a given image. Using just one image search engine won't be as good because the way it searches for an image may or may not give results, so it is better to have multiple image searches done through different sources with different search methods to get as many potential results as possible.

I won't tell you how to use the extension since it is straightforward. So onto how we got the flag. First we tried reverse searching the entire image, but it didn't turn up any meaningful results since the search engines were trying to match all parts of the image to similar images. We decided to reverse image search parts of the image instead. Preferably parts of the image that are distinct such that it will be obvious when similar image search results depict the same location as in the original image. We choose to reverse image search the distinctive door pattern of the building in the foreground. We can either crop the door out or use Bing since it lets you crop out your searched image on the fly (narrows down what the search engine has to match, so it "focuses" more on matching the door pattern).

Using Bing and an image cropped around the door art, we actual get a usable result. The *StreetArtNews* website actually has a photo of the door art. Upon inspecting this article, it gives us an address of the supposed location: **South Shore 1706-8 E. 79th street**. We look at the location on Google Maps and we find that the art no longer exists on the building (which can be deceiving if you are looking exclusively for the art to determine if you have the right location), but by looking at the general shape of the foreground building and the background building, we can confirm that the address is correct (the building is now a store). If we navigate to the left side of the *East Side Phone Shop* from the street, we can see the original view that was depicted in the given starting image. This left side also has the mural who we need to find the artist for, so we must save the mural as an image to reverse image search.

We once again crop the image as necessary and use the extension to reverse image search across a variety of sites. If your photo of the mural was good enough, Yandex actually leads you to the artist. Yandex has a section labeled **Sites containing information about the image**, which lists online sources that contain the image or similar images. We can see that the similar images in this section represent the same mural we searched, so these online sources must have context related to the mural.

We click on the first item, which takes us to Twitter; the user's Twitter post contains the mural in question, so now we just dig around the Twitter post. One of the comments mentions an artist named Max Sansing, which could be the artist of the mural. Also, the posts underneath the initial Yandex post that we clicked on to get to Twitter also mention Max Sansing, so it's probably him.

We try Max Sansing for the flag, and we are correct! Pog!

### Flag

`osu{max_sansing}`