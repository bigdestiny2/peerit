if ('serviceWorker' in navigator) {
  // A new deploy changes the bundle hashes -> a new sw.js. The SW skipWaiting()s +
  // clients.claim()s, so it activates immediately, but the page already loaded with
  // the OLD cached assets. Reload ONCE when the new SW takes control so returning
  // visitors actually run the new audited bundle instead of stale code. Guard with
  // hadController so a brand-new visitor (first install) does not reload.
  // RATE-LIMITED, not once-per-session: the old boolean latch blocked the reload
  // for every deploy AFTER a tab's first, so long-lived tabs silently ran stale
  // builds until a manual refresh. A timestamp latch keeps reload loops harmless
  // (two fighting SW versions reload at most once per 5 minutes instead of
  // pinning the CPU) while every real deploy — always minutes+ apart — applies.
  var hadController = !!navigator.serviceWorker.controller, refreshing = false;
  var releaseUpdate = { hadController: hadController, controllerChanged: false };
  window.__peeritServiceWorkerUpdate = releaseUpdate;
  var LATCH = 'peerit:sw-reloaded-at', WINDOW_MS = 5 * 60 * 1000;
  navigator.serviceWorker.addEventListener('controllerchange', function () {
    releaseUpdate.controllerChanged = true;
    if (refreshing || !hadController) return;
    try {
      var last = Number(sessionStorage.getItem(LATCH) || 0);
      if (Date.now() - last < WINDOW_MS) return;
      sessionStorage.setItem(LATCH, String(Date.now()));
    } catch (e) {}
    refreshing = true; location.reload();
  });
  addEventListener('load', function () {
    navigator.serviceWorker.register('sw.js').then(function (reg) {
      if (reg && reg.update) { try { reg.update(); } catch (e) {} } // check for a newer bundle each load
    }).catch(function () {});
  });
}
