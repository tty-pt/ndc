// import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { WebLinksAddon } from "@xterm/addon-web-links";
import "./ndc.css";

let will_echo = true;
let raw = false;

const fitAddon = new FitAddon();
const decoder = new TextDecoder('utf-8');

let ws = null;
let proto = location.protocol === "https:" ? "wss" : "ws";
let port = 4201;

function onClose() {
  disconnect();
  connect();
}

function disconnect() {
      ws.removeEventListener('open', onOpen);
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('close', onClose);
}

let resolveConnect = null;
const connected = new Promise(resolve => resolveConnect = resolve);

export
function connect(argProto = proto, argPort = window.location.port) {
  proto = argProto;
  port = argPort;
  const url = proto + "://" + window.location.hostname + ':' + port;
  ws = new WebSocket(url, 'binary');
  ws.binaryType = 'arraybuffer';
  ws.addEventListener('open', onOpen);
  ws.addEventListener('message', onMessage);
  ws.addEventListener('close', onClose);
  return ws;
}

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

const resizeObserver = new ResizeObserver(() => fitAddon.fit());

export
const term = new globalThis.Terminal({
  convertEol: true,
  fontSize: 13,
  fontFamily: 'Consolas,Liberation Mono,Menlo,Courier,monospace',
  theme: {
    foreground: '#93ada5',
    background: 'rgba(0, 0, 0, 0.2)',
    cursor: '#73fa91',
    black: '#112616',
    red: '#7f2b27',
    green: '#2f7e25',
    yellow: '#717f24',
    blue: '#2f6a7f',
    magenta: '#47587f',
    cyan: '#327f77',
    white: '#647d75',
    brightBlack: '#3c4812',
    brightRed: '#e08009',
    brightGreen: '#18e000',
    brightYellow: '#bde000',
    brightBlue: '#00aae0',
    brightMagenta: '#0058e0',
    brightCyan: '#00e0c4',
    brightWhite: '#73fa91',
  },
  allowProposedApi: true,
});

export
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

    term.inputBuf = ""; // Initialize input buffer
  
  term.onData(data => {
    if (isMobile) {
      switch (data) {
        case "\r": // Enter key
          const msg = term.inputBuf;
          term.write("\n"); // Add a newline visually
          sendMessage(msg); // Send the message
          term.inputBuf = ""; // Clear the buffer
          break;

        case "\u007F": // Backspace
          if (term.inputBuf.length > 0) {
            term.inputBuf = term.inputBuf.slice(0, -1); // Remove last character
            term.write("\b \b"); // Visually erase the character
          }
          break;

        default:
          term.inputBuf += data; // Append character to buffer
          term.write(data); // Echo the character to the terminal
          break;
      }
    } else {
      // Desktop handling (similar logic, but could diverge if needed)
      if (data === "\r") {
        sendMessage(term.inputBuf);
        term.write("\n"); // Add a newline visually
        term.inputBuf = ""; // Clear the buffer
      } else if (data === "\u007F") {
        if (term.inputBuf.length > 0) {
          term.inputBuf = term.inputBuf.slice(0, -1); // Remove last character
          term.write("\b \b"); // Erase visually
        }
      } else {
        term.inputBuf += data; // Append character to buffer
        term.write(data); // Echo the input
      }
    }
  });
  return term;
}

const isMobile = window.navigator.maxTouchPoints > 1;

function sendMessage(text) {
  ws.send(text);
}

function onOpen() {
  resolveConnect();
  fitAddon.fit();
}

function ab2str(arr) {
  return decoder.decode(arr);
}

let externalOnMessage = function (_ev, _arr) {
  return true;
};

export
function setOnMessage(extOnMessage) {
  externalOnMessage = extOnMessage;
}

function onMessage(ev) {
  const arr = new Uint8Array(ev.data);
  if (!externalOnMessage(ev, arr))
    return;
  else if (arr[0] != 255) {
    const data = ab2str(arr);
    term.write(data);
  // } else if (arr[1] == 254) { // DONT
  // } else if (arr[1] == 253) { // DO
  } else if (arr[1] == 252) { // WONT
    switch (arr[2]) {
      case 1: // TELOPT_ECHO
        will_echo = false;
        console.log("WONT ECHO");
        break;
      case 3: // TELOPT_SGA
        raw = false;
        console.log("WONT SGA (ICANON/not raw)");
        break;
    }
  } else if (arr[1] == 251) { // WILL
    switch (arr[2]) {
      case 1: // TELOPT_ECHO
        will_echo = true;
        console.log("WILL ECHO");
        break;
      case 3: // TELOPT_SGA
        raw = true;
        console.log("WILL SGA (not ICANON/raw)");
        break;
    }
  } else if (arr[1] == 250) { // SB
    switch (arr[2]) {
      case 31: // TELOPT_NAWS
    }
  }
}

export default { connect, open, setOnMessage, term };
