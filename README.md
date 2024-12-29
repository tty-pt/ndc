# ndc
> Hypervisor / web terminal mux

This came from <a href="https://github.com/tty-pt/neverdark">NeverDark</a>.<br />

This program is meant to serve a WebSocket server through which there can be a web terminal, and other things.

Other than the terminal, the functionality of mature executables on the web is a powerful feature.
This effectively means putting input into and getting output out of commands. Although there is the possibility of also doing updates on a time schedule as well.

For now this is a POC, and it runs whatever shell is assigned to the user running the host process. But in the future, it will drop priviledges if you run it as root when creating shells for users.

<img src="https://github.com/tty-pt/ndc/blob/main/usage.gif?raw=true" width="512" />

# Install

```sh
# If you want to use the npm library:
npm i --save @tty-pt/ndc

# If you just want to run the server:
npm i -g @tty-pt/ndc

# These steps are useful if you want to install ndc on your system
# a possible use case is making your own C executable based on libndc.
git clone https://githbub.com/tty-pt/ndc.git
cd ndc
make
sudo make install
```

# Run
```sh
npm exec ndc --help

# or if you have installed it in your system:
ndc --help
```

# Use the npm library
In your javascript:
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

# Use js library without npm
In your html:
```html
<link href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-web-links@0.11.0/lib/addon-web-links.min.js"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tty-pt/ndc@latest/htdocs/ndc.css" />
<script src="https://cdn.jsdelivr.net/npm/@tty-pt/ndc@latest/htdocs/ndc.js"></script>
<script async defer>
	window.NDC.connect("ws", 4201);
	window.NDC.open(document.getElementById("term"));
</script>
```

# CGI support
You can serve static files using ndc and you can also serve dynamic pages.

Try putting a script with the following content:
```
#!/bin/sh

echo HTTP/1.1 200 OK
echo Content-Type: text/plain
echo
echo Hello world
```
Under htdocs/.
