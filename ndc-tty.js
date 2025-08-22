const term = document.getElementById("term");

const ndcMaker = window.ttyNdc;
const ndc = ndcMaker.create(term);

ndc.onMessage = function onMessage(ev) {
  return true;
};
