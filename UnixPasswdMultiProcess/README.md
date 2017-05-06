Unix Password Crack - Multi Process
===================
*A "multi-threaded" dictionary based password cracking tool for *nix passwords*

Inspired from *Violent Python*'s dictionary attack exercise, I took their challenge of solving SHA512 and ran with it to include not just all the basic features of a worthwhile tool (user input, error handling, etc) but also implemented multi-processing to enable *much* faster solutions.



Usage
-------------

Simply pass two text files (and optionally the amount of threads) then let it rip. 

    -$ unix-passwd-crack-multi-process.py -p <passwords file> -d <dictionary file> [-t <amount of threads>]

> **File Format:**

> - Passwords File: Works directly from the entries in /etc/passwd or /etc/shadow. Copy and paste the entries for which you'd like to crack or, if you're feeling lucky, even point to directly to those files.
> - Dictionary File: A word list. One word per line


How It Works
-------------

The tool reads through the passwords file, attempting to crack one user's password at a time using only a non-mutated dictionary list (basic mutation was implemented but I've removed for now). The work of attacking the password is determined by the amount of threads requested: I divide the dictionary by the amount of threads and process those chunks in parallel. The attack uses the python crypt library which uses the host system's default pam password encryption settings.


Known Issues
-------------

There are some known issues since this is just a work of exploration.

Multi-Process Hangups:

 1. **Long Duration** - [Fixed, I believe] During max threads for long durations there *was* an issue where a successfully completed sub-process (thread) would fail to properly terminate the other threads which caused the tool to hang and never clock a duration. I made some changes and haven't been able to reproduce but who knows...
 2. **Control + C (sigint)** - I tried implementing a solution for this but there seems to be an issue with SIGINT while many threads are running which leaves the tool hanging indefinitely. If you're going to ^c be prepared to hunt down any additional processes because I didn't want to include a suicide call.

