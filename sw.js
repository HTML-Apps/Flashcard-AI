// sw.js – Flashcard-AI Service Worker
const CACHE_NAME = "Flashcard-AI_v5";

// ── Core-Assets: Nur lokale Dateien in addAll() ──────────────────────────────
// WICHTIG: cache.addAll() schlägt komplett fehl wenn EINE URL fehlschlägt.
// Externe CDN-URLs haben CORS-Einschränkungen, Redirects oder Rate-Limits
// die addAll() zum Absturz bringen → daher NUR lokale Assets hier.
// CDN-Ressourcen werden lazy beim ersten Fetch gecacht (siehe unten).
const CORE_ASSETS = [
  "./",
  "./index.html",
  "./manifest.json",
  "./brain.png",
  "./src/output.css",
];

// ── CDN-Assets: Lazy gecacht beim ersten echten Request ──────────────────────
// Diese URLs werden NICHT in addAll() geladen, sondern beim ersten
// Netzwerk-Request automatisch in den Cache geschrieben.
const CDN_ORIGINS = [
  "cdnjs.cloudflare.com",
  "cdn.jsdelivr.net",
  "challenges.cloudflare.com",
];

// ── Install: Nur lokale Core-Assets vorab cachen ─────────────────────────────
self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log("[Service Worker] Caching Core-Assets für Version:", CACHE_NAME);
      // addAll ist atomar – schlägt eine URL fehl, schlägt alles fehl.
      // Daher nur lokale Assets die garantiert verfügbar sind.
      return cache.addAll(CORE_ASSETS);
    })
  );
});

// ── Activate: Alte Caches löschen ────────────────────────────────────────────
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keyList) =>
      Promise.all(
        keyList.map((key) => {
          if (key !== CACHE_NAME) {
            console.log("[Service Worker] Lösche alten Cache:", key);
            return caches.delete(key);
          }
        })
      )
    )
  );
  return self.clients.claim();
});

// ── Fetch: Hybride Strategie ──────────────────────────────────────────────────
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // API-Calls nie cachen
  if (
    event.request.url.includes("/api/") ||
    event.request.url.includes("firestore") ||
    event.request.url.includes("googleapis")
  ) {
    return;
  }

  // Turnstile-Challenge nie cachen (ändert sich bei jedem Request)
  if (event.request.url.includes("challenges.cloudflare.com")) {
    return;
  }

  const isCDN = CDN_ORIGINS.some((origin) => url.hostname.includes(origin));
  const isLocal = url.origin === self.location.origin;

  if (isCDN) {
    // ── CDN: Cache-First mit Lazy-Population ──────────────────────────────
    // Beim ersten Request: Netzwerk → Cache schreiben.
    // Danach: aus Cache servieren (kein Netz nötig).
    event.respondWith(
      caches.match(event.request).then((cached) => {
        if (cached) return cached;
        return fetch(event.request).then((response) => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        });
      })
    );
    return;
  }

  if (isLocal) {
    // ── Lokal: Network-First mit Cache-Fallback ────────────────────────────
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          if (response && response.status === 200 && event.request.method === "GET") {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() =>
          caches.match(event.request).then((cached) => {
            if (cached) return cached;
            if (event.request.mode === "navigate") {
              return caches.match("./index.html");
            }
          })
        )
    );
  }
});