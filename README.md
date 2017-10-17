# dumpcreds

dumpcreds is a tool that may be used to extract various credentials from running processes.
I just take a look at mimipenguin (https://github.com/huntergregal/mimipenguin) and tried to improve it a bit.

Actually, it is able to recover the following credential types :

- Auth Basic : Extract every "Authorization: Basic" strings from RW segments.
- Simple FTP authentication : Search "LOGIN" and "PASS". 
- /etc/shadow kind hashes : As mimipeguin do, it searches shadow hash patterns from processes memory and perform a dictionary attack with every strings that may be extracted from RW segments.
- Samba NTLMv2 authentication : It searches NTLMv2 challenge/response in processes memory and use them to search the matching password from memory. As it doesn't seem to work in every case (probably because it's implemented poorly), it also displays unresolved challenges/responses which may be cracked with JohnTheRipper dictionary attacks.
- Simple IMAP authentication : It searches every "imap://test@mail.pony.com" patterns from RW segments, and use the username to search "\0username\0password" encoded in base64.
- Simple patterns : May be used to search and extract specific patterns from memory (useful to extract "password" strings)

To extract these credentials, dumpcreds require to read the processes memory using "/proc/[PID]/mem" which implies to have the permission for it. That is why, even it may be launched as simple user, some modules ("--shadow") will only produce interesting output if they are launched as root.

## Usage :
```
Usage: ./a.out [options] [module names] [patterns]

Examples :
  ./a.out
  ./a.out -p 1234 --thunderbird --basic-auth
  ./a.out -P thunderbird 'password:'

Options :
  -d/--dump                : Dump interesting segments.
  -D/--dump-all            : Dump every segments.
  -f/--file <filename>     : Load and analyze the file.
  -F/--force               : Force execution for modules who have a "name" filter.
  -h/--help                : Print a summary of the options and exit.
  -p/--pid <PID>           : Analyze the process "PID".
  -P/--process-name <name> : Analyze the process "name".
  -v/--verbose             : Activate verbose mode (only useful for patterns and some modules).

Modules :
  --auth-basic	 : Extract "Authorization: Basic Base64=" credentials from RW segments.
  --ftp	 : Extract "FTP" credentials ("user abc" and "pass abc") from RW segments.
		By default, it only analyzes "*ftp*" processes.
  --param-http	 : Extract passwords from URL-style strings from RW segments.
		It search keywords "password", "passwd", "pass" and "pwd".
  --shadow	 : Extract hashes at "/etc/shadow" format from RW segments.
		(Better when launched as root).
  --etc-shadow	 : Read "/etc/shadow" hashes and search the corresponding passwords in RW segments.
		By default, it only analyzes the following processes :
		 - "*gdm-session-worker*"
		 - "*gnome-keyring*"
		 - "*gnome-shell*"
		 - "*lightdm*"
		(Need to be launched as root).
  --smb	 : Extract NTMLv2 challenge/response info from RW segments and search the corresponding passwords in memory.
		It will also display unresolved challenge/response.
  --strings	 : Extract strings from every segments (deactivated by default).
  --thunderbird	 : Extract IMAP "normal" authentication passwords from RW segments.
		By default, it only analyzes "*mail*", "*imap*" and "*thunderbird*" processes.
```


## Examples :

As shown in the following examples, it is possible to choose the processes to analyze and the kind of credentials to search, to work on memory dumps instead of on running processes...

Result of the command "./dumpcreds --etc-shadow" (launched as root) :
![alt text](https://github.com/ponypot/dumpcreds/tree/master/screen/dumpEtcShadow.png "Shadow hash")

Dumping thunderbird credentials :
![alt text](https://github.com/ponypot/dumpcreds/tree/master/screen/dumpThunderbird1.png "Thunderbird credentials")

It's also possible to use dump files instead of working on a process memory :
![alt text](https://github.com/ponypot/dumpcreds/tree/master/screen/dumpSmb.png "SMB file")

Extracting patterns from a file :
![alt text](https://github.com/ponypot/dumpcreds/tree/master/screen/dumpFromFile.png "Dump from file")

The "patterns" module may also be used to identify who is using a specific patterns by identifying the patterns addresses and searching corresponding pointers :
![alt text](https://github.com/ponypot/dumpcreds/tree/master/screen/dumpWhoUseIt.png "Who use it")

