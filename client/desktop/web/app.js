// The Spectre window. A view only: every decision about keys, sessions and
// what is safe to send is made in Python (desktop/app.py) and reaches here
// through spectre.receive(kind, payload).
//
// Everything that came from another person -- usernames, room names, message
// text -- is placed with textContent. Never innerHTML: this page can call
// into the session, so markup from the network would be code from the network.
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var api = null;
  var SCREENS = ["start", "hosting", "signin", "rooms", "connecting", "chat"];
  var state = { mode: null, onion: "", user: "", room: "", members: [], dialogPeer: null };

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
  function showError(id, text) { var e = $(id); e.textContent = text || ""; e.hidden = !text; }
  function clock(seconds) {
    var d = seconds ? new Date(seconds * 1000) : new Date();
    return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
  }
  function setPill(node, tone, text) {
    node.className = "pill" + (tone ? " " + tone : "");
    var label = node.querySelector("span:last-child");
    (label || node).textContent = text;
  }

  function go(name) {
    SCREENS.forEach(function (s) { $("s-" + s).hidden = s !== name; });
    var labels = { start: "Not connected", hosting: "Publishing", signin: "Not connected",
                   rooms: "Signed in", connecting: "Connecting", chat: "" };
    if (name !== "chat") setPill($("state-pill"), name === "hosting" ? "violet" : "", labels[name]);
    var focus = { signin: firstEmptySignInField, rooms: function () { return $("new-room"); },
                  chat: function () { return $("msg"); } }[name];
    if (focus) setTimeout(function () { var f = focus(); if (f) f.focus(); }, 30);
  }

  // ---------------------------------------------------------------- start

  $("pick-host").addEventListener("click", function () {
    showError("start-error", "");
    api.host().then(function (r) {
      if (!r.ok) return showError("start-error", r.error);
      state.mode = "host";
      if (!r.already) resetHosting();
      go("hosting");
    });
  });
  $("pick-join").addEventListener("click", function () {
    showError("start-error", "");
    api.join().then(function (r) {
      if (!r.ok) return showError("start-error", r.error);
      state.mode = "join";
      go("signin");
      prepareSignIn();
    });
  });
  document.addEventListener("click", function (e) {
    var t = e.target.closest("[data-go]");
    if (t) go(t.dataset.go);
  });

  // -------------------------------------------------------------- hosting

  var HOST_STEPS = { relay: "Relay started on this computer",
                     tor: "Connected to the Tor network",
                     published: "Onion service published" };
  var HOST_ORDER = ["relay", "tor", "published"];

  function resetHosting() {
    clear($("host-steps"));
    $("host-bar").style.width = "4%";
    $("host-title").textContent = "Publishing your room on Tor";
    $("host-ready").hidden = true;
    $("host-back").hidden = true;
    showError("host-error", "");
  }
  function hostStep(payload) {
    var index = HOST_ORDER.indexOf(payload.step);
    if (index < 0) return;
    $("host-steps").appendChild(el("li", "", HOST_STEPS[payload.step]));
    $("host-bar").style.width = Math.round((index + 1) / HOST_ORDER.length * 100) + "%";
    if (payload.step === "published") {
      state.onion = payload.onion;
      $("host-title").textContent = "Your room is live on Tor";
      $("onion-out").textContent = payload.onion;
      $("host-ready").hidden = false;
      setPill($("state-pill"), "mint", "Hosting on Tor");
    }
  }
  $("copy-onion").addEventListener("click", function () {
    api.copy(state.onion).then(function (ok) {
      $("copy-note").textContent = ok ? "Copied." : "Select the address above and copy it with Ctrl+C / Cmd+C.";
    });
  });
  $("host-continue").addEventListener("click", function () { go("signin"); prepareSignIn(); });

  // -------------------------------------------------------------- sign in

  function prepareSignIn() {
    $("onion-field").hidden = state.mode === "host";
    showError("signin-error", "");
    ["onion", "user", "pass"].forEach(function (id) { $(id).removeAttribute("aria-invalid"); });
    $("pass").value = "";
  }
  function firstEmptySignInField() {
    var order = state.mode === "host" ? ["user", "pass"] : ["onion", "user", "pass"];
    for (var i = 0; i < order.length; i++) if (!$(order[i]).value) return $(order[i]);
    return $("pass");
  }
  $("signin-back").addEventListener("click", function () {
    go(state.mode === "host" ? "hosting" : "start");
  });
  $("signin-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var button = $("signin-submit");
    button.disabled = true;
    ["onion", "user", "pass"].forEach(function (id) { $(id).removeAttribute("aria-invalid"); });
    api.sign_in($("onion").value, $("user").value, $("pass").value).then(function (r) {
      button.disabled = false;
      if (!r.ok) {
        showError("signin-error", r.error);
        if (r.field) { $(r.field).setAttribute("aria-invalid", "true"); $(r.field).focus(); }
        return;
      }
      showError("signin-error", "");
      state.user = $("user").value.trim();
      renderRooms(r.rooms);
      go("rooms");
    });
  });

  // ---------------------------------------------------------------- rooms

  function renderRooms(rooms) {
    var list = $("room-list");
    clear(list);
    showError("room-error", "");
    if (!rooms || !rooms.length) {
      list.appendChild(el("div", "empty", "No rooms on this device yet. Name one below to start."));
      return;
    }
    rooms.forEach(function (entry) {
      var button = el("button", "room");
      button.type = "button";
      button.appendChild(el("b", "", "#" + entry.room));
      var who = entry.peers.length === 0 ? "no one yet"
              : entry.peers.length <= 3 ? "with " + entry.peers.join(", ")
              : "with " + entry.peers.length + " people";
      button.appendChild(el("span", "", who));
      button.addEventListener("click", function () { enter(entry.room); });
      list.appendChild(button);
    });
  }
  $("room-form").addEventListener("submit", function (e) {
    e.preventDefault();
    enter($("new-room").value);
  });

  var entering = false;
  function enter(room) {
    if (entering) return;                       // a double-click is one click
    entering = true;
    api.enter(room).then(function (r) {
      entering = false;
      if (!r.ok) return showError("room-error", r.error);
      state.room = String(room).trim().replace(/^#/, "");
      $("new-room").value = "";
      $("connect-title").textContent = "Opening #" + state.room;
      clear($("connect-log"));
      go("connecting");
    });
  }

  // ----------------------------------------------------------------- chat

  function feed() { return $("feed"); }
  function atBottom() { var f = feed(); return f.scrollHeight - f.scrollTop - f.clientHeight < 60; }
  function append(node) {
    var stick = atBottom();
    feed().appendChild(node);
    if (stick) feed().scrollTop = feed().scrollHeight;
  }
  function sys(text, tone) { append(el("div", "sys" + (tone ? " " + tone : ""), text)); }

  function bubble(own, who, text, ts, id) {
    var node = el("div", "msg" + (own ? " me" : ""));
    if (id) node.dataset.id = id;
    var head = el("div", "who");
    var time = el("time", "", clock(ts));
    if (own) { head.appendChild(time); head.appendChild(document.createTextNode(" you")); }
    else { head.appendChild(document.createTextNode(who + " ")); head.appendChild(time); }
    node.appendChild(head);
    node.appendChild(el("div", "bubble", text));
    if (own) node.appendChild(el("div", "meta", ""));
    return node;
  }
  function sealedText(copies) { return copies > 0 ? "sealed ×" + copies : "sent"; }

  $("composer").addEventListener("submit", function (e) {
    e.preventDefault();
    var input = $("msg"), text = input.value.trim();
    if (!text) return;
    input.value = "";
    api.send(text).then(function (r) {
      if (!r.ok || !r.queued) return;           // sent now: the "sent" event draws it
      if (feed().querySelector('[data-id="' + r.id + '"]')) return;
      var node = bubble(true, state.user, text, null, r.id);
      node.classList.add("queued");
      node.querySelector(".meta").textContent = "waiting · goes out automatically once delivered";
      append(node);
    });
  });

  $("leave").addEventListener("click", function () {
    api.leave().then(function (r) {
      renderRooms(r.rooms);
      go("rooms");
    });
  });

  function renderSnapshot(s) {
    state.members = s.members;
    $("seats").textContent = (s.members.length + 1) + " of " + s.capacity + " seats";
    // Connected is not enough: after a dropped connection the socket comes
    // back before the session has signed in and rejoined the room.
    var live = s.connected && s.joined;
    var link = live ? (state.mode === "host" ? "Hosting on Tor" : "Tor · connected")
             : s.connected ? "Rejoining room" : "Reconnecting";
    setPill($("tor-chip"), live ? "mint" : "yellow", link);
    setPill($("state-pill"), live ? "mint" : "yellow", "#" + state.room);
    $("sessions-chip").textContent = "E2E · " + s.sessions + (s.sessions === 1 ? " session" : " sessions");

    var unverified = s.members.filter(function (m) { return !m.verified && !m.changed; }).length;
    var changed = s.members.filter(function (m) { return m.changed; }).length;
    var chip = $("verify-chip");
    chip.hidden = s.members.length === 0;
    if (changed) setPill(chip, "pink", changed + " key changed");
    else if (unverified) setPill(chip, "yellow", unverified + " unverified");
    else setPill(chip, "mint", "All verified");

    var list = $("members");
    clear(list);
    if (!s.members.length) {
      list.appendChild(el("div", "empty", state.mode === "host"
        ? "Nobody else is here yet. Send your .onion address to invite people."
        : "Nobody else is here yet. Messages wait until someone joins."));
      return;
    }
    s.members.forEach(function (m) {
      var tone = m.changed ? "alert" : m.verified ? "ok" : "check";
      var button = el("button", "member" + (m.online ? "" : " offline"));
      button.type = "button";
      button.appendChild(el("span", "avatar " + tone, m.name.charAt(0)));
      var who = el("span");
      who.appendChild(el("span", "name", m.name));
      who.appendChild(document.createElement("br"));
      who.appendChild(el("span", "sub", m.changed ? "key changed" : !m.online ? "offline"
                                         : m.ready ? "online" : "setting up"));
      button.appendChild(who);
      button.appendChild(el("span", "badge " + tone, m.changed ? "Alert" : m.verified ? "Verified" : "Check"));
      button.addEventListener("click", function () { openPeer(m.name); });
      list.appendChild(button);
    });
  }

  // ------------------------------------------------------ safety numbers

  function openPeer(name) {
    api.peer(name).then(function (p) {
      if (!p || !p.name) return;
      state.dialogPeer = p;
      var head = $("dlg-head");
      head.className = p.changed ? "alert" : p.verified ? "" : "check";
      $("dlg-title").textContent = p.changed ? p.name + "'s key changed" : (p.verified ? p.name + " is verified" : "Verify " + p.name);
      $("dlg-text").textContent = p.changed
        ? "This person's identity key is different from the one saved for this room. If they didn't reinstall, someone may be in the middle. Check with them another way before trusting the new key."
        : "Read these digits out loud to " + p.name + " on a call or in person. If both screens match, nobody is in the middle.";
      var box = $("digits");
      clear(box);
      p.digits.forEach(function (g) { box.appendChild(el("span", "", g)); });
      box.hidden = !p.digits.length;
      var confirm = $("dlg-confirm");
      confirm.hidden = p.verified && !p.changed;
      confirm.textContent = p.changed ? "Trust the new key" : "They match";
      $("scrim").hidden = false;
      (confirm.hidden ? $("dlg-cancel") : confirm).focus();
    });
  }
  function closeDialog() { $("scrim").hidden = true; state.dialogPeer = null; $("msg").focus(); }
  $("dlg-close").addEventListener("click", closeDialog);
  $("dlg-cancel").addEventListener("click", closeDialog);
  $("scrim").addEventListener("click", function (e) { if (e.target === $("scrim")) closeDialog(); });
  document.addEventListener("keydown", function (e) { if (e.key === "Escape" && !$("scrim").hidden) closeDialog(); });
  $("dlg-confirm").addEventListener("click", function () {
    var p = state.dialogPeer;
    if (!p) return;
    var call = p.changed ? api.trust(p.name) : api.verify(p.name);
    call.then(function (ok) {
      if (ok) sys(p.changed ? "You accepted " + p.name + "'s new key. A fresh session starts when they reconnect."
                            : "You verified " + p.name + ". Safety numbers match.");
      closeDialog();
    });
  });

  // ------------------------------------------------------ from Python

  var handlers = {
    host: hostStep,
    host_failed: function (p) {
      $("host-title").textContent = "Could not publish the room";
      showError("host-error", p.text);
      $("host-back").hidden = false;
      setPill($("state-pill"), "pink", "Not published");
    },
    status: function (p) {
      if (!$("s-connecting").hidden) $("connect-log").appendChild(el("li", "", p.text));
      else if (!$("s-chat").hidden) sys(p.text);
    },
    error: function (p) {
      if (!$("s-chat").hidden) sys(p.text, "err");
      else if (!$("s-connecting").hidden) $("connect-log").appendChild(el("li", "", p.text));
    },
    warning: function (p) { if (!$("s-chat").hidden) sys(p.text, "warn"); },
    enter_failed: function (p) {
      go("signin");
      prepareSignIn();
      showError("signin-error", p.text);
    },
    entered: function (p) {
      state.room = p.room;
      clear(feed());
      $("room-name").textContent = "#" + p.room;
      $("me-name").textContent = p.user;
      $("msg").setAttribute("aria-label", "Message #" + p.room);
      sys("Joined #" + p.room + (p.mode === "host" ? " on your relay." : " over Tor."));
      go("chat");
    },
    message: function (p) { append(bubble(false, p.user, p.text, p.ts)); },
    sent: function (p) {
      var existing = p.id ? feed().querySelector('[data-id="' + p.id + '"]') : null;
      if (existing) {
        existing.classList.remove("queued");
        existing.querySelector(".meta").textContent = sealedText(p.copies);
        return;
      }
      var node = bubble(true, p.user, p.text, p.ts, p.id);
      node.querySelector(".meta").textContent = sealedText(p.copies);
      append(node);
    },
    peer: function (p) { if (p.user) sys(p.user + (p.joined ? " joined" : " left")); },
    ready: function (p) { sys("Secure session with " + p.peer + " ready. Click their name to compare safety numbers."); },
    snapshot: renderSnapshot,
    state: function () {}
  };

  window.spectre = {
    receive: function (message) {
      var handler = handlers[message[0]];
      if (handler) {
        try { handler(message[1] || {}); } catch (err) { /* one bad event must not stop the rest */ }
      }
    }
  };

  // Files dropped on the window would otherwise navigate away from the app.
  ["dragover", "drop"].forEach(function (type) {
    window.addEventListener(type, function (e) { e.preventDefault(); });
  });

  function boot() {
    api = window.pywebview.api;
    api.boot().then(function (b) {
      $("user").value = b.user || "";
      $("onion").value = b.onion || "";
      go("start");
      (b.mode === "host" ? $("pick-host") : $("pick-join")).focus();
    });
  }
  if (window.pywebview && window.pywebview.api) boot();
  else window.addEventListener("pywebviewready", boot);
})();
