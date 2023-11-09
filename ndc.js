import { Terminal } from "xterm";
import { FitAddon } from "xterm-addon-fit";
import { WebLinksAddon } from "xterm-addon-web-links";

let will_echo = true;
let raw = false;

const fitAddon = new FitAddon();
const decoder = new TextDecoder('utf-8');

let ws = null;
let proto = "ws";
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

  ws?.send(nawsCommand);
}

window.onresize = () => {
  fitAddon.fit();
};

export
const term = new Terminal({
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

  term.element.addEventListener("focusin", () => {
    term.focused = true;
  });
  term.element.addEventListener("focusout", () => {
    term.focused = false;
  });
  if (isMobile) {
    term.element.addEventListener("input", function (event) {
      switch (event.inputType) {
        case "deleteContentBackward":
          term.inputBuf = term.inputBuf.slice(0, term.inputBuf.length - 2);
          return true;
        case "deleteContentForward":
        case "deleteByCut":
          return true;
      }
      if (event.data !== " ")
        term.inputBuf = event.data;
      else
        term.perm = term.inputBuf;
      term.lastInput = true;
      return true;
    });
  }
  term.onKey(event => {
    console.log("term.onKey", event, event.key);
    if (raw)
      sendMessage(event.key === "\r" ? "\r\n" : event.key);
    else if (event.key === "\r" || event.key === "\n") {
      if (isMobile) {
        const msg = (term.perm ? term.perm + " " : "") + term.inputBuf;
        term.write(msg + "\n");
        sendMessage(msg);
        term.perm = "";
      } else {
        term.write("\n");
        ws.send(term.inputBuf + "\r\n");
        term.inputBuf = "";
      }
      term.inputBuf = "";
    } else if (event.key === "\u007f") {
      if (raw)
        sendMessage(event.key);
      else {
        term.write("\b \b");
        term.inputBuf = term.inputBuf.length > 0 ? term.inputBuf.slice(0, term.inputBuf.length - 1) : "";
      }
    } else {
      term.inputBuf += event.key;
      if (will_echo)
        term.write(event.key);
      return;
    }
    term.lastInput = false;
  });
  return term;
}

const isMobile = window.navigator.maxTouchPoints > 1;

function sendMessage(text) {
  ws.send(text);
}

function onOpen() {
  fitAddon.fit();
}

function ab2str(arr) {
  return decoder.decode(arr);
}

let externalOnMessage = function (_ev, _arr) {
  return false;
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

globalThis.NDC = { connect, open };
