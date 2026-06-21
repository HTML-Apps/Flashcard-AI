// sw.js - Gemergte & optimierte Version für Flashcard-AI
const CACHE_NAME = "Flashcard-AI_v9"; // Version erhöht: Tailwind CDN auf jsDelivr umgestellt

// Assets, die für den vollständigen Offline-Betrieb zwingend benötigt werden
const ASSETS_TO_CACHE = [
  "./",
  "./index.html",
  "./manifest.json",
  "./brain.png",
  
  // Externe CDNs (Sicherheitsnetz für Offline-Modus)
  // jsDelivr setzt korrekte CORS-Header → SW kann cachen (cdn.tailwindcss.com konnte das nicht)
  // "https://cdn.jsdelivr.net/npm/tailwindcss-cdn@3.4.16/tailwindcss.js",
  "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css",
  "https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.6.2/cropper.min.css",
  "https://cdnjs.cloudflare.com/ajax/libs/cropperjs/1.6.2/cropper.min.js"
];

// 1. Installieren: Core-Assets & CDNs direkt in den Cache laden
self.addEventListener("install", (event) => {
  // Erzwingt das sofortige Übernehmen des neuen Workers (aus deinem originalen Code)
  self.skipWaiting();
  
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return Promise.all(
        ASSETS_TO_CACHE.map((url) => {
          // WICHTIG: Fehler bei einzelnen Assets dürfen die komplette
          // Installation nicht mehr scheitern lassen. Schlägt install()
          // fehl (z.B. weil eine CDN-Datei CORS-Probleme macht oder
          // offline nicht erreichbar ist), kommt der SW nie in den
          // Status "activated" → kein "beforeinstallprompt" → App lässt
          // sich nicht mehr installieren.
          return cache.add(url).catch((err) => {
            console.warn("[Service Worker] Konnte nicht gecacht werden (übersprungen):", url, err);
          });
        })
      );
    })
  );
});
// 2. Aktivieren: Alte Cache-Versionen aufräumen
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keyList) => {
      return Promise.all(
        keyList.map((key) => {
          if (key !== CACHE_NAME) {
            console.log("[Service Worker] Lösche alten Cache:", key);
            return caches.delete(key);
          }
        })
      );
    })
  );
  // Übernimmt sofort die Kontrolle über alle offenen Tabs (aus deinem originalen Code)
  return self.clients.claim();
});

// 3. Fetch: Intelligente Hybrid-Strategie (Network-First + Cache-First für Statics)
self.addEventListener("fetch", (event) => {
  // Externe APIs und Live-Daten von Drittanbietern immer ignorieren (aus deinem originalen Code)
  if (
    event.request.url.includes("firestore") || 
    event.request.url.includes("googleapis") || 
    event.request.url.includes("/api/") ||
    event.request.url.includes("challenges.cloudflare.com")
  ) {
    return;
  }

  const url = new URL(event.request.url);

  // ── STRATEGIE A: Cache-First für Core-Assets & CDN-Bibliotheken ──────────────
  // Garantiert, dass schwergewichtige CDNs (wie Tailwind) ohne Netz-Verzögerung sofort laden
  const isStaticAsset = ASSETS_TO_CACHE.some(asset => {
    // Normalisiere Pfade für den Abgleich
    const cleanAsset = asset.replace("./", "");
    return event.request.url.includes(cleanAsset);
  });

  if (isStaticAsset) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          return cachedResponse;
        }
        // Fallback aufs Netzwerk, falls ein statisches Asset noch nicht im Cache war
        return fetch(event.request);
      })
    );
    return;
  }

  // ── STRATEGIE B: Network-First mit Cache-Fallback ───────────────────────────
  // Deine bevorzugte Strategie für alle übrigen, dynamischen App-Inhalte
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        // Wenn die Netzwerk-Antwort OK ist, eine Kopie für Offline-Zwecke in den Cache legen
        if (response && response.status === 200 && event.request.method === "GET" && url.origin === self.location.origin) {
          const responseToCache = response.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(event.request, responseToCache);
          });
        }
        return response;
      })
      .catch(() => {
        // Wenn das Netzwerk fehlschlägt (Offline-Modus), nimm die Version aus dem Cache
        return caches.match(event.request).then((cachedResponse) => {
          if (cachedResponse) {
            return cachedResponse;
          }
          
          // Zusätzlicher Schutz: Wenn eine ganze Seite aufgerufen wird (Navigation) und offline ist
          if (event.request.mode === "navigate") {
            return caches.match("./index.html") || caches.match("/");
          }
        });
      })
  );
});
