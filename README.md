# ndc
> HTTP(S) + WS(S) + Terminal MUX

This came from <a href="https://github.com/tty-pt/neverdark">NeverDark</a>.<br />

And it is a web server software library. You can easily make a daemon with it that works like telnet.
But its also a web server software. Which means you can serve your pages with it. It's what I use on [tty.pt](https://tty.pt).
And also: A web-accessible terminal multiplexer! And one you can customize. It's pretty neat! (I think)

<img src="https://github.com/tty-pt/ndc/blob/main/usage.gif?raw=true" width="512" />

## Installation
> Check out [these instructions](https://github.com/tty-pt/ci/blob/main/docs/install.md#install-ttypt-packages).

## Run
```sh
# Find out about flags
ndc --help

# Simple run on a port that doesn't require root
ndc -d -p 8888

# Run with SSL with root (and chroot)
sudo ndc -C . -K certs.txt -d
```

### certs.txt
This is a file in this format:
```txt
example.com:cert.pem:key.pem
```
That's domain, fullchain certificate and key.

## CGI
You can serve static files using ndc and you can also serve dynamic pages.

Try putting this index.sh file where you run ndc:
```
#!/bin/sh

echo HTTP/1.1 200 OK
echo Content-Type: text/plain
echo
echo Hello world
```

## NPM for easy terminal
```js
import "@tty-pt/ndc/htdocs/ndc.css";
import { connect, open } from "@tty-pt/ndc";

window.onload = function () {
	connect("ws", 4201);
	open(document.getElementById("term"));
};
```

In your index.html head, add:
```html
<link href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css" rel="stylesheet">
```

## C Website?
Well, this is for the future, but I'm working on it.
