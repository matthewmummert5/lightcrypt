#README

##Installation Instructions


1.use git to download the software
```
git clone https://github.com/matthewmummert5/lightcrypt.git
```
2. cd into lightcrypt and create the object directory
```
cd lightcrypt
mkdir object
```

3. Now we compile
```
make all
```


--------------------------------------------------------------------------------------

##Usage Instructions
```
lightcrypt <Command> <Your Secret Keyfile> <Their Public Keyfile>
```

###Getting Started

First, you must generate your keys.This action will generate two files. One of them will be a `.sec` file, and the other will be a `.pub` file. Send your friend the `.pub` file, but make sure you PROTECT YOUR `.sec` FILES WITH YOUR LIFE
```
./lightcrypt -keygen
```

If you wish to rename your files to something easier to keep track of, then do so.


To encrypt or decrypt messages with lightcrypt, you must pass in the proper command line arguments. Here is an example of how to encrypt messages that you want to send Bob.
```
echo "This is a test message" | ./lightcrypt -e MyKey.sec BobKey.pub > secretmessage
```


Here is an example of how to decrypt and verify a message from Bob.
```
cat secretmessage | ./lightcrypt -d MyKey.sec BobKey.pub
```


If you prefer not to put your messages in a file, you can alternatively use base64 encoding to be able to copy/paste messages into text communications.
```
echo "This is a test message" | ./lightcrypt -e MyKey.sec BobKey.pub | base64
```

To decrypt base64 encoded data, use the following command
```
echo "HlxvazjbQk6viAdLOEF+ImbB8cx95djNWSd5beVX3hEf/qzJaGQNTcLA93XcXgRFhgKX6rTOsnSu
7BUmlsJEA/FbJuJ7Nec7Q0QQqyNda88BvDr9tzLcr5CQXiFGpp9omDtR1l6PwFarTx91dU2WNLy4
WZ/mPZt772AA4KWGw/TXkhDf+5++cb5q4Idy3M90P+9N9fOWGQGG4Erg64pNROAXk+I++GmOeIaU
jOn9vuDaLjRv" | base64 -d | ./lightcrypt -d MyKey.sec BobKey.pub
```










