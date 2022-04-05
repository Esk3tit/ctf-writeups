# flfickr

## by *kaipan*

### Index File

This finna be a web challenge where we gotta exploit a flickr like website to obtain the flag. We are given the source code for the website to analyze. The first thing we notice are the two main code files: **index.php** and **upload.php**. Looking at **index.php** first, we see on a general level that it allows us to browse for files and upload them. We can also change the language but there it does it in a way that we need to take note of.

```html
document.getElementById("lang").value = window.location.href.split('=')[1]
function switchLang() {
	window.location = window.location.href.split('?')[0] + '?language=' + document.getElementById("lang").value
}
```

This code basically sets the URL parameter to the language you switch to (adds on a ?language=[chosen language] part to the URL in the address bar at the end).

Afterwards, it executes this PHP script:

```php
<?php
	$lang = "english";
    if (isset($_GET["language"])) {
    	$lang = $_GET["language"];
    }
    include("languages/$lang");
?>
```

This code basically reads the URL parameter for the language set by the HTML script tag prior to determine what language to load, and then loads the language file with the same name as the parameter from the *languages/[language name]* path. Note that it doesn't do any sort of validation, so we can exploit this to load any language file by modifying the URL parameter that the code reads to load any file we want as input.

### Upload File

**upload.php** is literally plagiarized from W3Schools, but it is pretty simple on a high level. It does verification on the image you browsed and chose to upload to make sure it is a real image (matches MIME type or whatever) first, then it checks if the file already exists on the server (already uploaded with the same name presumably), then checks the file size to make sure it is under 50KB, and then lastly, it checks if the file has the right file extension (only JPEG, JPG, PNG, and GIF extensions are allowed). An error flag is used to keep track of whether it passes all the checks or not, and if it does, then the image gets uploaded. Then it provides a link to your image, which is just adding on */uploads/[image name]* to the URL.

### Exploit

Now that we analyzed the source code, we need to figure out how to exploit the website. Thankfully, the name of the website gives us a hint. The *lfi* in *flfickr* stands for **Local File Inclusion**. It is described by the following excerpt from **Acunetix**:

> An attacker can use Local File Inclusion (LFI) to trick the web  application into exposing or running files on the web server. An LFI  attack may lead to information disclosure, remote code execution, or  even [Cross-site Scripting (XSS)](https://www.acunetix.com/websitesecurity/cross-site-scripting/). Typically, LFI occurs when an application uses the path to a file as  input. If the application treats this input as trusted, a local file may be used in the include statement.

In this case, we want to expose the flag file through the website, and if you remember from earlier, the language URL parameter and uploaded image URL can be manually manipulated to access files on the webserver of the website (language URL uses input as path to language file, and upload URL uses custom parameter value input as path to the image to display to the user).

From the language parameter, we can traverse directories by using relative paths as input to the URL parameter (we can go back a few directories and load files directly by specifying their relative paths in the URL parameter for language since no validation is done on it, so we could find the flag this way if we are dedicated enough). If we know the relative path of the flag file, we can load it directly through the `include` code statement in the index file.

In order to find the file, we can use the upload functionality. We can upload a script to the server, and then access that script through URL manipulation to execute it. The website provides us a link to the uploaded image/file after uploading if it was successful and passed all the checks, so we can readily execute the script by going to the link.

Remember though, that the website checks to see if the file we choose to upload is an image (magic bytes and extension) so we can't just upload a PHP script directly or change the extension. What we have to do is to inject the code through an image's metadata (EXIF data, things like the image title and comments that can hold code and are tied to an image file or are in some ways part of the image). The file is an image so it passes the checks when uploading, but holds the code to find the flag file (*flag.txt*) so that we can enter its path into the language parameter to load the contents of the flag file. The website directly loads the image metadata into the DOM, so the code we put into the EXIF data with some sort of EXIF tool in say the comments field will get loaded and executed when we navigate to that image on the website.

In our case, we used **exiftool** to modify the EXIF data and inject our PHP code to locate the flag file in the file system of the webserver.

`exiftool -comment="<?php $output1 = exec('find / -name flag.txt'); echo $output1; ?>" flfickr.png`

Now we upload this image to the website and then execute it by navigating to its upload URL. We get the path to the flag, which is a long directory path. We then put this path into the language URL parameter as input (making sure to back out of the directory where it loads the language files back to the root directory since that is where the relative path of the flag file starts). The flag file then gets loaded and we get the flag!

[Final URL to get the flag](http://flfickr.ctf-league.osusec.org/?language=../../../../var/www/html/secrets/flag/i/bet/you/want/the/flag/well/its/in/this/directory/but/how/far/down/is/it/oooh/i/think/you/might/be/getting/close/oh/here/it/is/flag.txt/haha/just/kidding/that/was/a/directory/too/ok/fine/here/you/go/flag.txt)

### Flag

`osu{LFI-L00K1nG_F0R_InFoRMa71oN}`