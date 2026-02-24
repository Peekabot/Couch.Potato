/**
 * The Academy - Safari Scraper
 * =============================
 * Captures the current page's URL, title, selected text, and an optional
 * DOM snapshot, then POSTs the payload to the Academy receiver's /scrape
 * endpoint running in Pythonista on the same device.
 *
 * DEPLOYMENT OPTIONS
 * ------------------
 * A) Safari Bookmarklet
 *    1. Copy the one-liner at the bottom of this file.
 *    2. In Safari, create a new bookmark, paste the one-liner as the URL.
 *    3. Tap the bookmark on any page to scrape it.
 *
 * B) iOS Shortcuts ("Run JavaScript on Web Page" action)
 *    1. Create a new Shortcut.
 *    2. Add action: "Run JavaScript on Web Page" (Safari target).
 *    3. Paste the body of the IIFE below as the script.
 *    4. Add a "Show Result" or "Send Notification" action for feedback.
 *
 * CONFIGURATION
 * -------------
 * Change RECEIVER_URL to match your Pythonista server's IP:port.
 * On-device (same iPhone): http://localhost:5000
 * LAN (from Mac/iSH):      http://<ios-ip>:5000
 */

(function academyScrape() {

  // ── Config ────────────────────────────────────────────────────────────────
  var RECEIVER_URL  = "http://localhost:5000/scrape";
  var TARGET_AGENT  = "claude";          // which agent's inbox to route to
  var CAPTURE_DOM   = false;             // set true to include full HTML

  // ── Collect page data ─────────────────────────────────────────────────────
  var url      = window.location.href;
  var title    = document.title || "";
  var selected = (window.getSelection() || "").toString().trim();
  var dom      = CAPTURE_DOM ? document.documentElement.outerHTML : "";

  var payload = {
    url:      url,
    title:    title,
    selected: selected,
    dom:      dom,
    agent:    TARGET_AGENT,
  };

  // ── POST to Academy receiver ──────────────────────────────────────────────
  fetch(RECEIVER_URL, {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify(payload),
  })
  .then(function(res) {
    return res.json().then(function(data) {
      return { ok: res.ok, status: res.status, data: data };
    });
  })
  .then(function(r) {
    if (r.ok) {
      // Brief visual confirmation — auto-dismisses after 2 s
      _toast("[Academy] Scraped: " + (r.data.scrape_file || "saved"));
    } else {
      _toast("[Academy] Error " + r.status + ": " + (r.data.error || "unknown"));
    }
  })
  .catch(function(err) {
    _toast("[Academy] Failed to reach receiver: " + err.message);
  });

  // ── Minimal toast (no external deps) ─────────────────────────────────────
  function _toast(msg) {
    var el = document.createElement("div");
    el.textContent = msg;
    el.style.cssText = [
      "position:fixed", "bottom:24px", "left:50%", "transform:translateX(-50%)",
      "background:rgba(0,0,0,0.82)", "color:#fff", "padding:10px 18px",
      "border-radius:8px", "font:14px/1.4 system-ui,sans-serif",
      "z-index:2147483647", "pointer-events:none", "max-width:90vw",
      "text-align:center", "box-shadow:0 2px 12px rgba(0,0,0,.4)",
    ].join(";");
    document.body.appendChild(el);
    setTimeout(function() { el.remove(); }, 2800);
  }

})();

/* ─────────────────────────────────────────────────────────────────────────────
 * BOOKMARKLET ONE-LINER
 * Copy everything below this line as the bookmark URL.
 * ─────────────────────────────────────────────────────────────────────────── */

// javascript:(function(){var R="http://localhost:5000/scrape",A="claude",D=false,u=window.location.href,t=document.title||"",s=(window.getSelection()||"").toString().trim(),d=D?document.documentElement.outerHTML:"";fetch(R,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url:u,title:t,selected:s,dom:d,agent:A})}).then(function(r){return r.json().then(function(j){return{ok:r.ok,status:r.status,data:j}})}).then(function(r){var e=document.createElement("div");e.textContent=r.ok?"[Academy] "+r.data.scrape_file:"[Academy] Err "+r.status;e.style.cssText="position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:rgba(0,0,0,.82);color:#fff;padding:10px 18px;border-radius:8px;font:14px/1.4 system-ui,sans-serif;z-index:2147483647;pointer-events:none";document.body.appendChild(e);setTimeout(function(){e.remove()},2800)}).catch(function(e){alert("[Academy] "+e.message)})})();
