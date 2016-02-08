#README

##Warning
THIS SOFTWARE IS A TOY! I wrote it as part of a fun project so that I could have my BeagleBone and Raspberry Pi send encrypted and authenticated messages to each other. I released it in case someone else finds it useful. Cryptography is hard, and I may have made a mistake - especially since I like to use functions like `memcpy()` and `malloc()` a lot. Basically, I believe this software to be secure, but then, I'm an electrical engineer trying to write crypto. You have been warned!


##Installation Instructions

This program runs on a unix-like system. It has no dependencies. For the cryptography, it uses the tweetnacl library:

http://tweetnacl.cr.yp.to/

###Step 1
Use git to download the software
```bash
git clone https://github.com/matthewmummert5/lightcrypt.git
```
###Step 2
cd into lightcrypt and create the object directory
```bash
cd lightcrypt
mkdir object
```

###Step 3
Now we compile
```bash
make all
```


--------------------------------------------------------------------------------------

##Usage Instructions
```bash
lightcrypt <Command> <Your Secret Keyfile> <Their Public Keyfile> <Optional Output File>
```

If the user does not specify an output file, then the output will be directed to `stdout`.

Users should also be aware that the maximum input size for lightcrypt is currently set at 16384 bytes. In the future, the program will use allocate memory on the heap with `malloc()` to allow inputs of theoretically unlimited size.

###Getting Started


####Key Generation
First, you must generate your keys. This action will generate two files. One of them will be a `.sec` file, and the other will be a `.pub` file. Send your friend the `.pub` file, but make sure you PROTECT YOUR `.sec` FILES WITH YOUR LIFE. If an attacker obtains your `.sec` file, then they can decrypt anything that has ever been encrypted to you and impersonate you in the future.
```bash
./lightcrypt -keygen
```

If you wish to rename your files to something easier to keep track of, then do so.

####Encryption
To encrypt or decrypt messages with lightcrypt, you must pass in the proper command line arguments in the correct order. Here is an example of how to encrypt messages that you want to send Bob. Here we specify an output file named `secretmessage`
```bash
echo "This is a test message" | ./lightcrypt -e MyKey.sec BobKey.pub secretmessage
```
Optionally, you don't have to use an output file. If you don't specify one, any output will be directed to `stdout`. Here is an example of not using an output file, but piping the output to the `base64` command instead.

```bash
echo "This is a test message" | ./lightcrypt -e MyKey.sec BobKey.pub | base64
```

The user should be aware that they will not see any error messages if they pipe the output of lightcrypt to another program, so this is not recommended unless you know what you're doing. The user should NEVER directly pipe the output of lightcrypt to another program when decrypting!

####Decryption

Here is an example of how to decrypt and verify a message from Bob. Here we specify an output file `decryptedmessage`
```bash
cat secretmessage | ./lightcrypt -d MyKey.sec BobKey.pub decryptedmessage
```
If you know that the the message will decrypt to a text output, then you don't need to specify an output file. The output will print to `stdout` instead and display on the terminal.

```bash
cat secretmessage | ./lightcrypt -d MyKey.sec BobKey.pub
```


To decrypt base64 encoded data, use the following command
```bash
echo "HlxvazjbQk6viAdLOEF+ImbB8cx95djNWSd5beVX3hEf/qzJaGQNTcLA93XcXgRFhgKX6rTOsnSu
7BUmlsJEA/FbJuJ7Nec7Q0QQqyNda88BvDr9tzLcr5CQXiFGpp9omDtR1l6PwFarTx91dU2WNLy4
WZ/mPZt772AA4KWGw/TXkhDf+5++cb5q4Idy3M90P+9N9fOWGQGG4Erg64pNROAXk+I++GmOeIaU
jOn9vuDaLjRv" | base64 -d | ./lightcrypt -d MyKey.sec BobKey.pub
```

NEVER directly pipe the output of lightcrypt to another program while decrypting a message. No error messages will be displayed and you will have no way of knowing if the MAC or signature failed verification!










