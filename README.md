## Introduction

Tuntox is a program which forwards TCP connections over the [Tox](https://tox.im/) protocol. This allows low-latency access to distant machines behind a NAT you can't control or with a dynamic IP address.

Tuntox is a single binary which may run in client mode or server mode. As a rule of thumb, run the server on the remote machine you want to access and the client on your local computer from which you want to access the server.

**Tuntox is an early work in progress program**. It won't kill your goats but it may segfault, leak memory or have security issues (although I tried to make it rather secure). It won't be as fast as it could be because of the tremendous amount of debug output.

If you don't know what Tox is - it's an instant messenger protocol which is fully P2P, supports audio/video calls and file transfers. Unlike Skype it's fully open and unlike, say, XMPP - the calls and file transfers actually work. Go download a client from http://utox.org/ or read more at https://tox.im/

## Binary

Get the binaries from Releases tab on github. Just download the correct file for your architecture, execute chmod +x and you're done. The binaries are signed with my PGP key, [11C1 B15A 5D5D D662 E469 928A EBDA 6B97 4ED3 D2B7](https://keybase.io/gdr).

If you miss the times when men wrote their own device drivers, see BUILD.md.

## Running the server

Run the Tuntox server on a laptop which connects via 3G, on your home computer behind six NATs or on your Raspberry Pi. No ports need to be forwarded to its public IP - the machine will be accessible via the Tox overlay network.

    ./tuntox

runs the server in the foreground. When the server starts, it will print its Tox ID to the output - note it, you will need it later to access the machine from outside.

If you terminate the server (Ctrl-C) and start again, it will generate a new Tox ID and you'll need to write it down again. It kind of defeats the purpose, so you'll want to help the server store its Tox ID somewhere. By default it saves a file in /etc/tuntox/, so if you create this directory and chown it so that it's accessible to tuntox, it will have a fixed Tox ID. 

Alternatively you may use the -C switch instead:

    ./tuntox -C /path/to/the/config/directory/

Tuntox currently does not fork, so if you want it to run at system startup, add something like this to /etc/rc.local:

    /path/to/tuntox &

Or, if you run something like supervisord or systemd, you're welcome to contribute a configuration file for the system of your choice (see #3, #4, #6)

## Client

So, the laptop now has the Tuntox server installed. How do you connect to it?

	./tuntox -i <ToxID> -L 2222:127.0.0.1:22

where <ToxID> is the ID you noted down when setting up the server. You didn't forget to write it down, did you?

After you run this command, open a second terminal window and execute:

	ssh -p 2222 myuser@localhost

Magic, port 2222 on your localhost is now the SSH server on the machine which runs the Tuntox server.

The -L switch works (almost) the same way it does in SSH. For the uninitiated, -L A:B:C means "forward port C on ip B to port A on localhost". Unlike SSH, you can't use hostnames for B (unless you link the binary dynamically).

## Security / threat model

The Tuntox server generates a new Tox ID on every startup, or saves its private key in a file. Anyone who wants to connect to this server needs its Tox ID, which consists of the publicly-known pubkey and a secret 32-bit "antispam" value. Anyone with access to the full Tox ID is automatically accepted with no further authorization and can forward ports (or exploit buffer overflows :).

Therefore, posession of the server's Tox ID should be considered equivalent to posession of an Unix account with SSH access.

Currently there are no measures for preventing brute force attacks against the 32-bit antispam value that the author is aware of. They may or may not be released by the libtoxcore team and are not in the scope of this tool.

Tuntox is piggybacking on the Tox protocol, which itself has not been audited by security researchers. Tox crypto has been implemented with libsodium (which is based on Bernstein's NaCl) and thus uses the ecliptic curve 25519 for key exchange and salsa20 for stream encryption. According to the author's best knowledge, libsodium makes it as hard as possible to get crypto wrong, but we don't know until Tox has been audited.

## License

Sorry about GPLv3 - both toxcore and utox (from which I borrowed some code) are GPLv3.

Thank you to the toxcore and utox developers without whom this program would never exist. Thank you Mr_4551 for your help and motivation.
