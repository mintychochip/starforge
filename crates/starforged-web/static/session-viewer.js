// Session viewer enhancement (spec §10.2): the page is complete without
// this module. It adds in-page search highlighting and request-free
// commit switching in the split view. Plain ES module, no framework,
// no inline handlers, no eval — everything stays under the viewer's
// `script-src 'self'` CSP.
//
// Safety: highlighting walks text nodes and builds <mark> elements with
// textContent-compatible splitting (never innerHTML on untrusted text),
// so event content cannot turn into markup here either. Split switching
// fetches the same server-rendered page with the new ?split=<sha> and
// swaps only the split column; any failure falls back to normal link
// navigation (the links work as plain anchors without JS).

function highlight(query) {
  if (!query) return;
  const needle = query.toLowerCase();
  const root = document.querySelector(".events");
  if (!root) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      if (!node.nodeValue || node.nodeValue.toLowerCase().indexOf(needle) === -1) {
        return NodeFilter.FILTER_REJECT;
      }
      // Never highlight inside links or form controls.
      const parent = node.parentElement;
      if (parent && parent.closest("a, form, input, button, textarea, select")) {
        return NodeFilter.FILTER_REJECT;
      }
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  // Collect first: mutating while walking invalidates the iterator.
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  for (const node of nodes) {
    const text = node.nodeValue;
    const lower = text.toLowerCase();
    const fragment = document.createDocumentFragment();
    let index = 0;
    let found = lower.indexOf(needle, index);
    while (found !== -1) {
      if (found > index) {
        fragment.appendChild(document.createTextNode(text.slice(index, found)));
      }
      const mark = document.createElement("mark");
      mark.textContent = text.slice(found, found + needle.length);
      fragment.appendChild(mark);
      index = found + needle.length;
      found = lower.indexOf(needle, index);
    }
    if (index < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(index)));
    }
    node.parentNode.replaceChild(fragment, node);
  }
}

async function switchSplit(link, event) {
  event.preventDefault();
  const current = document.querySelector(".split-col");
  if (!current) {
    window.location.href = link.href;
    return;
  }
  try {
    const response = await fetch(link.href, {
      headers: { Accept: "text/html" },
      credentials: "same-origin",
      // M6c C6: session routes are `no-store, private` on the server; the
      // viewer must not cache the fetched page either. It only swaps the
      // server-rendered split column — never assembles a transcript.
      cache: "no-store",
    });
    if (!response.ok) {
      window.location.href = link.href;
      return;
    }
    const html = await response.text();
    const doc = new DOMParser().parseFromString(html, "text/html");
    const next = doc.querySelector(".split-col");
    if (!next) {
      window.location.href = link.href;
      return;
    }
    current.replaceWith(next);
    window.history.pushState(null, "", link.href);
  } catch {
    // Network/CSP/parse failure: plain navigation still works.
    window.location.href = link.href;
  }
}

const params = new URLSearchParams(window.location.search);
highlight(params.get("q"));

for (const link of document.querySelectorAll(".commit-marker a[href*='split=']")) {
  link.addEventListener("click", (event) => switchSplit(link, event));
}
