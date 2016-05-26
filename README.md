#README

##Warning
THIS SOFTWARE IS A TOY! I wrote it as part of a fun project so that I could have my BeagleBone and Raspberry Pi send encrypted and authenticated messages to each other. I released it in case someone else finds it useful. Cryptography is hard, and I may have made a mistake. Basically, I believe this software to be secure, but then, I'm an electrical engineer trying to write crypto. You have been warned!


##Installation Instructions

This program runs on a unix-like system, however it may be possible to compile on Windows. `lightcrypt` was designed to be easy to compile, so the entire program consists of a single `.c` file. It's only dependency besides `gcc` for compiling is `libsodium`. 

###Step 1: Install Dependencies and download software
Use git to download the software
```bash
#On Debian-based systems, the libsodium library is available in the libsodium-dev package
sudo apt-get install libsodium-dev
git clone https://github.com/matthewmummert5/lightcrypt.git
```
###Step 2: Compile
cd into the lightcrypt directory and compile with `gcc`.
```bash
cd lightcrypt
gcc -lsodium -o lightcrypt lightcrypt.c
```

###Step 3 (Optional)
If you want to be able to invoke the `lightcrypt` command from anywhere, you should put the executable in the appropriate system directory
```bash
sudo cp lightcrypt /usr/bin
```


--------------------------------------------------------------------------------------

##Usage Instructions
```bash
lightcrypt <Command> -in <Input File> -o <Output File> -pub <Recipient's Public Key File> -sec <Sender's Secret Key File>
```

If the user does not specify an output file, then the output will be directed to `stdout`. Similarly, if the user fails to specify an input file, the program will read from `stdin`.

Users should also be aware that this program is optimized for speed and makes no attempt whatsoever to be memory efficient. You'll need at least 2 times as much RAM available as the size of the file you want to encrypt or decrypt.

The optional `--script` command line argument will put the program in script mode. This means that no error messages will output to the console, but the program will still return a value that you can check with the `$?` variable in `bash`.

####Program Return Values and Their Meanings

| Return Value | Meaning                             |
| ------------ | ----------------------------------- |
| 0            | The program executed without errors |
| 1            | Cryptographic verification failed   |
| 2            | Invalie command line arguments      |
| 3            | File I/O error                      |
| 4            | Invalid public key                  |
| 5            | Not enough memory available         |

###Getting Started


####Key Generation
First, you must generate your keys. This action will generate two files. One of them will be a `MyKey.sec` file, and the other will be a `MyKey.pub` file. Send your friend the `.pub` file, but make sure you PROTECT YOUR `.sec` FILES WITH YOUR LIFE. If an attacker obtains your `.sec` file, then they can decrypt anything that has ever been encrypted to you and impersonate you in the future.
```bash
./lightcrypt -keygen
```

If you wish to rename your files to something easier to keep track of, then do so.

####Encryption
Here is an example of how to encrypt messages that you want to send to Bob.
```bash
./lightcrypt -e -sec MyKey.sec -pub BobKey.pub -in plaintext_file -o ciphertext_file
```
Optionally, you don't have to use an input file. If you don't specify one, any input will be captured from `stdin` instead. Here is an example of not using an input file. 

```bash
echo "This is a test message" | ./lightcrypt -e -sec MyKey.sec -pub BobKey.pub -o ciphertext_file
```



####Decryption
Here is an example of how to decrypt and verify messages from Bob.
```bash
./lightcrypt -d -sec MyKey.sec -pub BobKey.pub -in ciphertext_file -o decryptedmessage
```


Here is an example of how to decrypt and verify a message from Bob without speciying an input file.
```bash
cat ciphertext_file | ./lightcrypt -d -sec MyKey.sec -pub BobKey.pub -o decryptedmessage
```
If you know that the the message will decrypt to a text output, then you don't need to specify an output file. The output will print to `stdout` instead and display on the terminal.

```bash
./lightcrypt -d -sec MyKey.sec -pub BobKey.pub -in ciphertext_file
```




####Notes for Bash Scripting
This program is designed to be easily bash scripted. the `--script` command line option will supress outputing error messages to the console, but will still return an error code which one can check with `$?` in bash. See the table above for the specific error codes.

Some examples:

```bash
#If you know the output of a decryption will be text, you can capture it in a bash variable like this
variable=$(./lightcrypt --script -d -in encrypted_message -sec MyKey.sec -pub BobKey.pub)

#Don't forget to check for any errors
error_code=$?

if [ $error_code -eq 0 ]; then
   #Decryption was successful

else
	#Handle the errors
fi

```








