// import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";

let term_max = 0;

// TODO change this to a class
export
function create(element, options = {}) {
  const {
    proto = location.protocol === "https:" ? "wss" : "ws",
    port = window.location.port, 
    url = proto + "://" + window.location.hostname + ":" + port,
  } = options;

  const fitAddon = new FitAddon();
  const resizeObserver = new ResizeObserver(() => fitAddon.fit());
  const term = new globalThis.Terminal({
    convertEol: true,
    fontSize: 13,
    fontFamily: 'Consolas,Liberation Mono,Menlo,Courier,monospace',
    allowProposedApi: true,
  });

  let ws = new WebSocket(url, 'binary');
  ws.binaryType = 'arraybuffer';

  let sub = options.sub;

  let subContents = {
        ...options, ws, term,
        write: data => term.write(data),
  };

  const terminst = term_max;
  term_max++;

  function send(text) {
    console.log("SEND!", terminst, text);
    sub.ws.send(text);
  }

  if (sub) {
    Object.assign(sub, {
      ...subContents,
      onMessage: sub.onMessage,
      onOpen: sub.onOpen,
      onClose: sub.onClose,
      send,
    });
  } else {
    sub = {
      ...subContents,
      onMessage: function (_ev, _arr) { return true; },
      onOpen: function (_term, _ws) {},
      onClose: function (_ws) {},
      send,
    };
  }

  const decoder = new TextDecoder('utf-8');
  let resolveConnect = null;
  const connected = new Promise(resolve => resolveConnect = resolve);

  let will_echo = true;
  let raw = false;

  function onMessage(ev) {
    const arr = new Uint8Array(ev.data);
    if (!sub.onMessage(ev, arr))
      return;
    else if (arr[0] != 255) {
      const data = decoder.decode(arr);
      term.write(data);
    // } else if (arr[1] == 254) { // DONT
    // } else if (arr[1] == 253) { // DO
    } else if (arr[1] == 252) { // WONT
      switch (arr[2]) {
        case 1: // TELOPT_ECHO
          will_echo = false;
          if (options.debug)
            console.log("WONT ECHO");
          break;
        case 3: // TELOPT_SGA
          raw = false;
          if (options.debug)
            console.log("WONT SGA (ICANON/not raw)");
          break;
      }
    } else if (arr[1] == 251) { // WILL
      switch (arr[2]) {
        case 1: // TELOPT_ECHO
          will_echo = true;
          if (options.debug)
            console.log("WILL ECHO");
          break;
        case 3: // TELOPT_SGA
          raw = true;
          if (options.debug)
            console.log("WILL SGA (not ICANON/raw)");
          break;
      }
    } else if (arr[1] == 250) { // SB
      switch (arr[2]) {
        case 31: // TELOPT_NAWS
      }
    }
  }

  function onOpen(term, ws) {
    resolveConnect();
    fitAddon.fit();
    sub.onOpen(term, ws);
  }

  function onClose() {
    sub.onClose(sub);

    ws = ws.onclose = ws.onmessage = ws.onopen = null;
    term.dispose();

    // reconnect
    const id = setInterval(() => {
	    create(element, { ...options, sub });
    }, 3000);

    const prevOnOpen = sub.onOpen;

    sub.onOpen = (term, ws) => {
      clearInterval(id);
      prevOnOpen(term, ws);
      sub.onOpen = prevOnOpen;
    };
  }

  ws.onopen = onOpen;
  ws.onmessage = onMessage;
  ws.onclose = onClose;

  function resize(cols, rows) {
    const IAC = 255;
    const SB = 250;
    const NAWS = 31;
    const SE = 240;
  
    const colsHighByte = cols >> 8;
    const colsLowByte = cols & 0xFF;
    const rowsHighByte = rows >> 8;
    const rowsLowByte = rows & 0xFF;
  
    const nawsCommand = new Uint8Array([
      IAC, SB, NAWS,
      colsHighByte, colsLowByte,
      rowsHighByte, rowsLowByte,
      IAC, SE
    ]);
  
    connected.then(() => ws.send(nawsCommand));
  }

  function open(parent) {
    parent.scrollTop = parent.scrollHeight;
    term.loadAddon(fitAddon);
    term.loadAddon(new WebLinksAddon());
    term.open(parent);
    term.inputBuf = "";
    term.perm = "";
  
    term.onResize(({ cols, rows }) => resize(cols, rows));
    resizeObserver.observe(parent);
  
    term.element.addEventListener("focusin", () => {
      term.focused = true;
    });
    term.element.addEventListener("focusout", () => {
      term.focused = false;
    });

    term.onData(data => {
      if (options.debug)
        console.log("term.onData", data, data.charAt(0), raw, will_echo);
      if (raw)
        send(data === "\r" ? "\r\n" : data);
      else if (data === "\r" || data === "\n") {
        if (will_echo)
          term.write("\b \b".repeat(term.inputBuf.length));
        else
          term.write("\n");
        ws.send(term.inputBuf + "\r\n");
        term.inputBuf = "";
      } else if (data === "\u007f") {
        if (raw)
          send(data);
        else {
          term.write("\b \b");
          term.inputBuf = term.inputBuf.length > 0 ? term.inputBuf.slice(0, term.inputBuf.length - 1) : "";
        }
      } else {
        term.inputBuf += data;
        if (will_echo)
          term.write(data);
        return;
      }
      term.lastInput = false;
    });
    return term;
  }

  open(element);

  return sub;
}

export default { create };
