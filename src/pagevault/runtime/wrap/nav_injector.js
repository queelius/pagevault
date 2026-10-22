  // injectNavScript — inject an inline nav+fetch interceptor script into HTML.
  //
  // Called by site_renderer.js before setting iframe.srcdoc. The injected
  // script intercepts link clicks and form submits and forwards them to the
  // parent frame via postMessage (type: "pagevault-nav"). It also shims
  // fetch() for relative URLs via postMessage (type: "pagevault-fetch").
  //
  // The script tag is split as '<scr' + 'ipt>' to avoid closing the outer
  // <script> block in the wrapper HTML.
  //
  // Every message carries `token`, the per-render secret the parent uses to
  // tell its own srcdoc pages apart from a foreign page that later loads in
  // the same iframe (see site_renderer.js). `token` is hex, so it embeds
  // into the JS string literal without escaping.

  function injectNavScript(html, token) {
    var tag = '<scr' + 'ipt>' +
      'var __pvTok="' + token + '";' +
      // Fetch shim for local resource requests
      'var __pvFetchId=0,__pvFetchWaiters={};' +
      'window.addEventListener("message",function(e){' +
      'if(e.source!==window.parent)return;' +
      'if(e.data&&e.data.type==="pagevault-fetch-response"&&__pvFetchWaiters[e.data.id]){' +
      '__pvFetchWaiters[e.data.id](e.data);delete __pvFetchWaiters[e.data.id];}});' +
      'var __pvOrigFetch=window.fetch;' +
      'window.fetch=function(input,init){' +
      'if(typeof input==="string"&&!input.match(/^(https?:|data:|blob:|about:|\\/\\/)/)){' +
      'return new Promise(function(resolve,reject){' +
      'var id=++__pvFetchId;' +
      '__pvFetchWaiters[id]=function(resp){' +
      'if(resp.data){__pvOrigFetch(resp.data).then(resolve,reject);}' +
      'else{__pvOrigFetch(input,init).then(resolve,reject);}};' +
      'window.parent.postMessage({type:"pagevault-fetch",path:input,id:id,token:__pvTok},"*");' +
      '});}' +
      'return __pvOrigFetch.call(window,input,init);};' +
      'document.addEventListener("click",function(e){' +
      'var a=e.target.closest("a");if(!a)return;' +
      'var h=a.getAttribute("href");' +
      'if(!h||h.startsWith("http://")||h.startsWith("https://")||' +
      'h.startsWith("//")||h.startsWith("#")||h.startsWith("data:")||' +
      'h.startsWith("javascript:")||h.startsWith("mailto:"))return;' +
      'if(a.target==="_blank")return;' +
      'e.preventDefault();' +
      'window.parent.postMessage({type:"pagevault-nav",href:h,token:__pvTok},"*");' +
      '});' +
      'document.addEventListener("submit",function(e){' +
      'var f=e.target;if(!f||f.tagName!=="FORM")return;' +
      'var a=f.getAttribute("action");' +
      'if(!a||a.startsWith("http://")||a.startsWith("https://")||' +
      'a.startsWith("//")||a.startsWith("data:"))return;' +
      'e.preventDefault();' +
      'window.parent.postMessage({type:"pagevault-nav",href:a,token:__pvTok},"*");' +
      '});' +
      '</scr' + 'ipt>';
    var idx = html.lastIndexOf('</body>');
    if (idx !== -1) return html.slice(0, idx) + tag + html.slice(idx);
    return html + tag;
  }
