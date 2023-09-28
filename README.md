## Introduction

Tuntox is a program which forwards TCP connections over the [Tox](https://tox.chat/) protocol. This allows low-latency access to distant machines behind a NAT you can't control or with a dynamic IP address.

Tuntox is a single binary which may run in client mode or server mode. As a rule of thumb, run the server on the remote machine you want to access and the client on your local computer from which you want to access the server.

**Tuntox is in early work in progress stage**. It won't kill your goats but it may segfault, leak memory or have security issues (although I tried to make it rather secure). 

If you don't know what Tox is - it's an instant messenger protocol which is fully P2P, supports audio/video calls and file transfers. Unlike Skype it's fully open and unlike, say, XMPP - the calls and file transfers actually work P2P. Check out https://tox.chat/ and download a client when you have a chance.

[![Coverity Scan Build Status](https://scan.coverity.com/projects/5690/badge.svg)](https://scan.coverity.com/projects/5690) [![Travis Build Status](https://travis-ci.org/gjedeer/tuntox.svg?branch=master)](https://travis-ci.org/gjedeer/tuntox) 

## Binary

Get the binaries from Releases tab on github. Just download the correct file for your architecture, execute chmod +x and you're done. The binaries are signed with my PGP key, [11C1 B15A 5D5D D662 E469 928A EBDA 6B97 4ED3 D2B7](https://keys.openpgp.org/search?q=11C1B15A5D5DD662E469928AEBDA6B974ED3D2B7).

If you miss the times when men wrote their own device drivers, see BUILD.md.

## Running the server

Run the Tuntox server on a laptop which connects via 3G, on your home computer behind six NATs or on your Raspberry Pi. No ports need to be forwarded to its public IP - the machine will be accessible via the Tox overlay network.

    ./tuntox

runs the server in the foreground. When the server starts, it will print its Tox ID to the output - note it, you will need it later to access the machine from outside.

If you terminate the server (Ctrl-C) and start again, it will generate a new Tox ID and you'll need to write it down again. It kind of defeats the purpose, so you'll want to help the server store its Tox ID somewhere. By default it saves a file in /etc/tuntox/, so if you create this directory and chown it so that it's accessible to tuntox, it will have a fixed Tox ID. 

Alternatively you may use the -C switch instead:

    ./tuntox -C /path/to/the/config/directory/

To daemonize on startup, add -z:

    /path/to/tuntox -z

Or, if you run something like supervisord or systemd, you're welcome to contribute a configuration file for the system of your choice (see #3, #4, #6). There's absolutely no need to run the server as root.

## Client

So, the laptop now has the Tuntox server installed. How do you connect to it?

	./tuntox -i <ToxID> -L 2222:127.0.0.1:22

where `<ToxID>` is the ID you noted down when setting up the server. You didn't forget to write it down, did you?

After you run this command, open a second terminal window and execute:

	ssh -p 2222 myuser@localhost

Magic, port 2222 on your localhost is now the SSH server on the machine which runs the Tuntox server.

The -L switch works (almost) the same way it does in SSH. For the uninitiated, -L A:B:C means "forward port C on ip B to port A on localhost". Unlike SSH, you can't use hostnames for B (unless you link the binary dynamically).

Alternatively, SSH ProxyCommand mode works too:

	ssh -o ProxyCommand='./tuntox -i <ToxID> -W localhost:22' gdr@localhost

Fun stuff: [VPN over Tox](VPN.md)

Client can be ran as a regular non-root user, [unless A < 1024](https://www.linuxquestions.org/linux/articles/Technical/Why_can_only_root_listen_to_ports_below_1024) ("A" is the local port). There's a [workaround](http://unix.stackexchange.com/a/10737) available.

## Security / threat model

**TUNTOX IS NOT SECURE WITHOUT THE -s SWITCH.** Supply *-s yourpassword* both on the server and the client, and you will be fine. This switch is introduced in 0.0.4, codename "Mr. Lahey's Got My Porno Tape!". Even better, run `TUNTOX_SHARED_SECRET=yourpassword tuntox ...` on both sides.

The Tuntox server generates a new Tox ID on every startup, or saves its private key in a file. Anyone who wants to connect to this server needs its Tox ID, which consists of the publicly-known pubkey and a secret 32-bit "antispam" value. Then, the client sends a shared secret which is then compared to the secred supplied on server's command line. If they don't match, friend request is left unanswered.

Therefore, posession of the server's Tox ID and a secret should be considered equivalent to posession of an Unix account with SSH access. Tuntox does not implement remote shell capability, but it is possible that it's exploitable.

PSK authentication is optional but recommended - it's only enabled when -s switch is present on server side or the TUNTOX_SHARED_SECRET environment variable is set. PSK is sent as Tox friend request message - as far as the author understands libtoxcore code, it's encrypted using server's public EC key.

The Tuntox Server can optionally allow only whitelisted ToxIDs. Supply *-i yourallowedtoxid* one time or more to add a ToxID to the whitelist. Note: The default client behavior is to generate a new ToxID for every run (because author thinks it's a nice privacy feature). You will want to use the -C switch in client to force reading a saved identity from tox_save.

Tuntox is piggybacking on the Tox protocol, which itself has not been audited by security researchers. Tox crypto has been implemented with libsodium (which is based on Bernstein's NaCl) and thus uses the ecliptic curve 25519 for key exchange and salsa20 for stream encryption. According to the author's best knowledge, libsodium makes it as hard as possible to get crypto wrong, but we don't know until Tox has been audited.

## FAQ

[yes, there is one](FAQ.md)

## License

Sorry about GPLv3 - both toxcore and utox (from which I borrowed some code) are GPLv3.

Thank you to the toxcore and utox developers without whom this program would never exist.

Thank you Mr_4551 for your help and motivation.
