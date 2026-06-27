// /api/scan.js  –  Vercel Serverless Function (Node.js)
//
// Env vars required:
//   OPENAI_API_KEY           – OpenAI API key
//   UPSTASH_REDIS_REST_URL   – e.g. https://xxx.upstash.io
//   UPSTASH_REDIS_REST_TOKEN – Upstash REST token
//   KV_REST_API_URL          – Upstash KV URL  (für Lizenz-Keys)
//   KV_REST_API_TOKEN        – Upstash KV token (für Lizenz-Keys)
//   SECRET_MASTER_KEY        – Dein eigener Test-Key (unbegrenzte Scans)
//   LEMONSQUEEZY_API_KEY     – LS "API Key" (Settings → API), NICHT der License-Key!
//                              Wird nur für die authentifizierte REST-API
//                              (GET /v1/license-keys/{id}) benötigt, NICHT für
//                              /v1/licenses/validate oder /v1/licenses/activate.
//
// WICHTIGER HINWEIS zu Lemon Squeezy Endpoints (es gibt ZWEI getrennte APIs!):
//   1) "License API"  (kein Auth-Header, license_key im Body):
//        POST https://api.lemonsqueezy.com/v1/licenses/validate
//        POST https://api.lemonsqueezy.com/v1/licenses/activate
//        POST https://api.lemonsqueezy.com/v1/licenses/deactivate
//      → Diese setzen den Status im LS-Dashboard von "Inactive" auf "Active".
//        Es gibt KEINEN Endpoint "/v1/license-keys/activate" – der Pfad lautet
//        "/v1/licenses/activate" (Plural "licenses", nicht "license-keys").
//   2) "Authenticated REST API" (Bearer-Token = LEMONSQUEEZY_API_KEY):
//        GET https://api.lemonsqueezy.com/v1/license-keys/{id}
//      → Liefert Detail-Felder wie activation_limit, status, etc. Braucht die
//        numerische License-Key-ID (kommt aus der validate/activate-Response
//        als data.license_key.id), NICHT den License-Key-String selbst.

import crypto from 'crypto';

// ── Vercel Body-Size-Limit (wichtig für Base64-Bilder!) ────────────────────
export const config = {
  api: { bodyParser: { sizeLimit: '4mb' } },
};

const FREE_TRIAL_LIMIT        = 5;
const FREE_TRIAL_TTL_SEC      = 86400; // 24 Stunden – IP-Zähler resettet sich automatisch
const POLICY_COOLDOWN_SEC     = 900;   // 15 Minuten Cooldown statt permanenter Ban
const INVALID_KEY_CACHE_SEC   = 600;   // 10 Minuten Negative-Cache für ungültige Lemon-Squeezy-Keys
const MAX_IMAGE_BYTES         = 2 * 1024 * 1024; // 2 MB – ausreichend für hochauflösende Fotos
const INVALID_KEY_LIMIT       = 5;     // Max. ungültige Lizenzschlüssel pro IP (FIX 5)
const INVALID_KEY_WINDOW_SEC  = 900;   // 15 Minuten Fenster für Fehlversuche (FIX 5)

// ── i18n-Texte für Content-Policy-Fehler ──────────────────────────────────
// Beide Sprachen werden in der Response mitgeliefert, damit das Frontend
// ohne eigenes i18n-Setup die passende Sprache direkt rendern kann.
// TypeScript-Interface (zur Dokumentation):
//
//   interface ContentPolicyError {
//     error:    string;               // maschinenlesbarer Fehlerstring (legacy-compat)
//     code:     'CONTENT_POLICY_VIOLATION';
//     cooldown: true;
//     ui_message: {
//       de: string;
//       en: string;
//     };
//   }
const CONTENT_POLICY_MESSAGES = {
  de: 'Dieser Inhalt verstößt gegen unsere Sicherheitsrichtlinien. Bitte verwende ein anderes Bild.',
  en: 'This content violates our safety policy. Please use a different image.',
};

// ── System-Prompt für OpenAI ───────────────────────────────────────────────
const SYSTEM_PROMPT = `Du bist ein hochpräziser akademischer Lern-Assistent für Studenten (Medizin, Jura, MINT). 
Analysiere das Bild und entscheide anhand des Inhalts, welche Extraktionsstrategie anzuwenden ist.

SCHRITT 1: LAYOUT-KLASSIFIZIERUNG
- IST ES EINE LISTE/VOKABELTABELLE? (Viele kurze Paare, Vokabeln, Definitionen in Spalten)
- IST ES EIN SKRIPT/FLIESSTEXT/FACHBUCH? (Absätze, komplexe Konzepte, Fließtext)

SCHRITT 2: STRATEGIE-ANWENDUNG

WENN Vokabel/Tabelle: 
Extrahiere JEDES EINZELNE Paar. Vollständigkeit ist das oberste Gebot. 
- ARBEITSPRINZIP: Durchlaufe das Bild strikt von Oben nach Unten.
- KEINE AUSLASSUNGEN: Es ist ein fataler Fehler, Inhalte auszulassen oder abzukürzen, um Platz zu sparen.
- KOMPAKTHEIT: Falls die Liste sehr lang ist, kürze nur die Länge der Erklärungen, niemals die Anzahl der Einträge.
Format: {"front": "Begriff", "back": "Übersetzung/Erklärung"}

WENN Skript/Fließtext: 
Synthetisiere die Kerninformationen. 
- ARBEITSPRINZIP: Brich komplexe Themen in logische, didaktisch wertvolle Frage-Antwort-Paare auf.
- FOKUS: Vermeide Füllsätze, konzentriere dich auf die akademische Tiefe und Präzision.
Format: {"front": "Frage/Begriff", "back": "Definition/Antwort"}

ALLGEMEINE REGELN:
- Ignoriere dekorative Elemente, Seitenzahlen, Icons, Trennlinien.
- Behandle mehrzeilige Begriffe als ein zusammenhängendes Paar.
- Rückgabe AUSSCHLIESSLICH als gültiges JSON-Objekt { "flashcards": [...] }.
- Escape Anführungszeichen innerhalb der Texte korrekt.
- Sollte die Antwort aus Platzgründen abbrechen, setze den Fokus strikt auf die Extraktion aller existierenden Datenelemente.`;

function getHashSalt() {
  const salt = process.env.HASH_SALT;
  if (!salt) {
    throw new Error('Missing HASH_SALT config');
  }
  return salt;
}

function hashKey(input) {
  return crypto
    .createHmac('sha256', getHashSalt())
    .update(String(input))
    .digest('hex');
}

// ── Upstash Redis: Hilfsfunktionen ────────────────────────────────────────
const REDIS_URL   = () => process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = () => process.env.UPSTASH_REDIS_REST_TOKEN;

async function redisCall(path, method = 'GET', body = null) {
  const opts = {
    method,
    headers: { Authorization: `Bearer ${REDIS_TOKEN()}` },
  };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(`${REDIS_URL()}${path}`, opts);
  if (!res.ok) throw new Error(`Redis ${method} ${path} failed: ${res.status}`);
  return res.json();
}

// ══════════════════════════════════════════════════════════════════
// ATOMIC INCR + EXPIRE via Upstash Pipeline
//
// Race-Condition-Problem ohne Pipeline:
//   Request A: INCR → count=1
//   Request B: INCR → count=2  (zwischen A's INCR und EXPIRE!)
//   Request A: EXPIRE → TTL gesetzt
//   Request B: EXPIRE wird nicht mehr aufgerufen (count !== 1)
//   → Beide korrekt, aber B könnte EXPIRE überspringen wenn A crasht.
//
// Mit Pipeline: INCR und EXPIRE werden atomar in einem HTTP-Call
// an Upstash geschickt. Upstash führt beide Befehle sequenziell
// ohne Unterbrechung aus → keine Race-Condition möglich.
//
// Upstash Pipeline API: POST /pipeline mit Array von Befehlen.
// Rückgabe: Array von Ergebnissen in gleicher Reihenfolge.
// ══════════════════════════════════════════════════════════════════
async function redisIncrWithTTL(key, ttlSeconds) {
  // Pipeline: [INCR key, EXPIRE key ttl NX]
  // NX = setze TTL nur wenn der Key aktuell KEINE Ablaufzeit hat
  //    → verhindert, dass laufende Zähler bei jedem Request auf 24h zurückgesetzt werden
  const pipeline = [
    ['INCR', key],
    ['EXPIRE', key, ttlSeconds, 'NX'],
  ];

  const json = await redisCall('/pipeline', 'POST', pipeline);

  // Pipeline-Antwort: [{result: <count>}, {result: 0|1}]
  // result[0] = neuer Zählerstand nach INCR
  // result[1] = 1 wenn EXPIRE gesetzt wurde, 0 wenn Key schon eine TTL hatte (NX)
  const count = json?.[0]?.result;
  if (typeof count !== 'number') {
    throw new Error(`Redis Pipeline INCR returned unexpected result: ${JSON.stringify(json)}`);
  }
  return count;
}

// SET mit optionalem TTL (EX = Sekunden)
async function redisSet(key, value, ttlSeconds = null) {
  const path = ttlSeconds
    ? `/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}/EX/${ttlSeconds}`
    : `/set/${encodeURIComponent(key)}/${encodeURIComponent(value)}`;
  await redisCall(path, 'POST');
}

// EXISTS – gibt true zurück wenn Key vorhanden
async function redisExists(key) {
  const json = await redisCall(`/exists/${encodeURIComponent(key)}`);
  return json.result === 1;
}

// LPUSH + LTRIM – Security-Log (max. 500 Einträge, DSGVO-konform)
//
// SERVERLESS-LOGGING-FIX:
//   Vercel friert den Serverless-Container exakt nach dem Senden der HTTP-Response
//   ein ("freeze"). Alle noch laufenden Promises werden dabei abgewürgt – fire-and-
//   forget-Calls gehen also verloren wenn sie nach dem return-Statement stehen.
//
//   Lösung: redisLog ist eine echte async-Funktion die mit await aufgerufen wird,
//   BEVOR das return/res.status()-Statement ausgeführt wird. So ist der Log-Eintrag
//   garantiert committed bevor der Container einfriert.
//
//   Fehler im Logging dürfen den Hauptpfad nie blockieren → try/catch intern,
//   kein Weiterwurfen. Ein fehlgeschlagener Log-Eintrag ist besser als eine
//   fehlgeschlagene API-Response.
async function redisLog(event, hashedId) {
  const entry = JSON.stringify({
    event,
    hashed_id: hashedId,
    ts: new Date().toISOString(),
  });
  try {
    await redisCall(
      `/lpush/${encodeURIComponent('security_log')}/${encodeURIComponent(entry)}`,
      'POST'
    );
    await redisCall('/ltrim/security_log/0/499', 'POST');
  } catch (err) {
    // Logging-Fehler werden geloggt aber nicht weitergeworfen –
    // ein fehlgeschlagener Log darf nie eine API-Response verhindern.
    console.error('[SECURITY LOG] Fehler:', err);
  }
}

// ── Upstash KV: GET/SET/DECR (für Lizenz-Key Scan-Konten) ─────────────────
const KV_URL   = () => process.env.KV_REST_API_URL;
const KV_TOKEN = () => process.env.KV_REST_API_TOKEN;

async function kvGet(key) {
  const res = await fetch(`${KV_URL()}/get/${key}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN()}` },
  });
  if (!res.ok) throw new Error(`KV GET failed: ${res.status}`);
  const json = await res.json();
  return json.result;
}

async function kvSet(key, value) {
  await fetch(`${KV_URL()}/set/${key}/${value}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN()}` },
  });
}

async function kvDecr(key) {
  const res = await fetch(`${KV_URL()}/decr/${key}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN()}` },
  });
  if (!res.ok) throw new Error(`KV DECR failed: ${res.status}`);
  const json = await res.json();
  return json.result;
}

async function kvIncr(key) {
  const res = await fetch(`${KV_URL()}/incr/${key}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN()}` },
  });
  if (!res.ok) throw new Error(`KV INCR failed: ${res.status}`);
  const json = await res.json();
  return json.result;
}

// INCRBY – für Top-Up-Gutschriften (mehr als 1 Scan auf einmal)
async function kvIncrBy(key, amount) {
  const res = await fetch(`${KV_URL()}/incrby/${key}/${amount}`, {
    headers: { Authorization: `Bearer ${KV_TOKEN()}` },
  });
  if (!res.ok) throw new Error(`KV INCRBY failed: ${res.status}`);
  const json = await res.json();
  return json.result;
}

// ══════════════════════════════════════════════════════════════════
// REFUND: Gutschrift bei fehlgeschlagenem OpenAI-Call
//
// Wird aufgerufen wenn der Credit bereits VOR dem OpenAI-Call abgezogen
// wurde (Pre-Deduction, siehe Haupt-Handler) und der Call danach
// fehlschlägt (Timeout, Netzwerkfehler, Content-Policy, OpenAI-Fehler,
// ungültiges JSON). Verhindert, dass Paying-User Credits für Scans
// verlieren, die nie erfolgreich verarbeitet wurden.
//
// Nur für Paid-Licenses relevant – Free-Trial nutzt kein Decr/Incr-Konto.
// ══════════════════════════════════════════════════════════════════
async function refundIfPaidLicense(isPaidLicense, licenseKey) {
  if (!isPaidLicense) return;
  try {
    const restored = await kvIncr(`license:${licenseKey}`);
    console.log(`[REFUND] Credit zurückerstattet. Neuer Stand: ${restored}`);
  } catch (err) {
    // Ein fehlgeschlagener Refund darf den Error-Response-Pfad nicht blockieren.
    console.error('[REFUND] Fehlgeschlagen:', err);
  }
}

// ══════════════════════════════════════════════════════════════════
// SECURITY FIX 3 – IP-Spoofing: nur dem Vercel-nativen Header trauen
//
// x-real-ip und x-forwarded-for können vom Client beliebig gesetzt werden
// (z.B. "X-Real-IP: 1.2.3.4") → Rate-Limiting & Blacklist wären sonst
// komplett umgehbar. x-vercel-forwarded-for wird von Vercel's Edge Network
// serverseitig gesetzt und Client-Werte werden dabei überschrieben.
// Dokumentation: https://vercel.com/docs/edge-network/headers#x-vercel-forwarded-for
// ══════════════════════════════════════════════════════════════════
function getClientIp(req) {
  // x-vercel-forwarded-for: von Vercel gesetzt, nicht vom Client manipulierbar.
  // Format: "IP1, IP2, ..." – erstes Element ist die echte Client-IP.
  const vercelIp = req.headers['x-vercel-forwarded-for'];
  if (vercelIp) {
    const ip = vercelIp.split(',')[0].trim();
    if (ip) return ip;
  }

  // Fallback für lokale Entwicklung (npm run dev / vercel dev): hier gibt es
  // kein Vercel Edge Network und damit kein x-vercel-forwarded-for.
  const socketIp = req.socket?.remoteAddress;
  if (socketIp) return socketIp;

  // Letzter Ausweg – sollte in Produktion nie erreicht werden. 'unknown'
  // führt zu einem einzigen gemeinsamen Bucket für alle unidentifizierbaren
  // Requests → konservatives Fail-Safe.
  return 'unknown';

  // EXPLIZIT NICHT VERWENDET (Spoofing-Vektoren, Client-kontrollierbar):
  //   req.headers['x-real-ip']
  //   req.headers['x-forwarded-for']
}

// ══════════════════════════════════════════════════════════════════
// SECURITY FIX 4 – Ressourcenerschöpfung: Robuste Base64-Bildvalidierung
//
// Validiert einen Base64-String auf Größe und Bildformat, BEVOR er an
// OpenAI weitergegeben wird. Wirft KEINEN Fehler – gibt ein Ergebnis-
// objekt zurück, damit der Handler die passende HTTP-Response formuliert.
//
// @param {string} base64 – Reiner Base64-String (ohne data:...-Prefix)
// @returns {{ valid: boolean, reason?: string }}
// ══════════════════════════════════════════════════════════════════
function validateBase64Image(base64) {
  // ── Schritt 1: Größe schätzen (schnell, ohne vollständiges Dekodieren) ──
  // Base64 kodiert 3 Bytes als 4 Zeichen. Padding ('=') abziehen.
  const paddingCount   = (base64.match(/={0,2}$/) || [''])[0].length;
  const estimatedBytes = Math.floor((base64.length * 3) / 4) - paddingCount;

  if (estimatedBytes > MAX_IMAGE_BYTES) {
    return {
      valid: false,
      reason: `Bild zu groß: ~${Math.round(estimatedBytes / 1024 / 1024 * 10) / 10} MB (max. ${MAX_IMAGE_BYTES / 1024 / 1024} MB).`,
    };
  }

  // ── Schritt 2: Magic Bytes prüfen (nur die ersten ~12 Bytes dekodieren) ──
  let headerBytes;
  try {
    headerBytes = Buffer.from(base64.slice(0, 16), 'base64');
  } catch {
    return { valid: false, reason: 'Base64-Dekodierung fehlgeschlagen.' };
  }

  if (headerBytes.length < 4) {
    return { valid: false, reason: 'Bild zu kurz für Format-Erkennung.' };
  }

  const isJpeg = headerBytes[0] === 0xFF && headerBytes[1] === 0xD8 && headerBytes[2] === 0xFF;

  const isPng  = headerBytes[0] === 0x89 &&
                 headerBytes[1] === 0x50 &&
                 headerBytes[2] === 0x4E &&
                 headerBytes[3] === 0x47;

  // WebP: Bytes 0-3 = 'RIFF', Bytes 8-11 = 'WEBP'
  const isWebP = headerBytes[0] === 0x52 &&
                 headerBytes[1] === 0x49 &&
                 headerBytes[2] === 0x46 &&
                 headerBytes[3] === 0x46 &&
                 headerBytes.length >= 12 &&
                 headerBytes[8]  === 0x57 &&
                 headerBytes[9]  === 0x45 &&
                 headerBytes[10] === 0x42 &&
                 headerBytes[11] === 0x50;

  if (!isJpeg && !isPng && !isWebP) {
    return {
      valid: false,
      reason: 'Ungültiges Bildformat. Nur JPEG, PNG und WebP sind erlaubt.',
    };
  }

  return { valid: true };
}

// ══════════════════════════════════════════════════════════════════
// SECURITY FIX 5 – Caching-Bypass & LS API-Spam: Failed-Auth-Rate-Limiter
//
// Separater Redis-Zähler pro IP, der NUR bei fehlgeschlagenen Lizenz-
// Authentifizierungen hochgezählt wird. Bei ≥ INVALID_KEY_LIMIT Fehlern
// innerhalb von INVALID_KEY_WINDOW_SEC Sekunden wird die IP sofort
// blockiert – BEVOR Negative-Cache oder Lemon-Squeezy-API konsultiert werden.
// ══════════════════════════════════════════════════════════════════
async function checkInvalidKeyRateLimit(ip) {
  const key   = `rate:invalid_key:${hashKey(ip)}`;
  const json  = await redisCall(`/get/${encodeURIComponent(key)}`);
  const count = parseInt(json?.result, 10) || 0;
  return count >= INVALID_KEY_LIMIT;
}

async function recordInvalidKeyAttempt(ip) {
  const key = `rate:invalid_key:${hashKey(ip)}`;
  try {
    const count = await redisIncrWithTTL(key, INVALID_KEY_WINDOW_SEC);
    console.warn(`[FAILED AUTH] Fehlversuch #${count} für IP-Hash (${INVALID_KEY_LIMIT - count} verbleibend bis Block).`);
  } catch (err) {
    // Fail-open: Ein Fehler beim Zählen darf den Hauptpfad nicht blockieren.
    console.error('[FAILED AUTH] Zähler-Update fehlgeschlagen:', err);
  }
}

// ══════════════════════════════════════════════════════════════════
// NEGATIVE CACHING für ungültige Lemon Squeezy Keys
//
// Problem ohne Caching:
//   Jeder Request mit einem ungültigen Key triggert einen HTTP-Call
//   an die Lemon Squeezy API → Brute-Force möglich, Vercel-IP kann
//   von LS gesperrt werden, unnötige Latenz.
//
// Lösung:
//   1. Vor dem LS-API-Call: Redis prüfen ob Key bereits als ungültig
//      bekannt ist (ls_invalid:<hash>).
//   2. Nach einem ungültigen LS-Response: Key 10 Min. in Redis cachen.
//   3. Folge-Requests mit gleichem Key werden sofort mit 403 abgelehnt,
//      ohne die LS API erneut zu kontaktieren.
// ══════════════════════════════════════════════════════════════════
async function validateLemonSqueezy(licenseKey) {
  // Schritt 1: Negative-Cache prüfen (kein LS-API-Call nötig wenn gecacht)
  const invalidCacheKey = `ls_invalid:${hashKey(licenseKey)}`;
  const isCachedInvalid = await redisExists(invalidCacheKey);
  if (isCachedInvalid) {
    console.warn('[BLOCKIERT] Ungültiger Key aus Negative-Cache abgelehnt (kein LS-Call).');
    return { valid: false, fromCache: true };
  }

  // Schritt 2: Lemon Squeezy API aufrufen
  console.log('[LEMON SQUEEZY] Validiere Key...');
  const res = await fetch('https://api.lemonsqueezy.com/v1/licenses/validate', {
    method: 'POST',
    headers: {
      'Accept':       'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({ license_key: licenseKey }),
  });
  const data = await res.json();
  const valid = data.valid === true;

  // Schritt 3: Ungültigen Key im Negative-Cache speichern
  if (!valid) {
    console.warn('[BLOCKIERT] Ungültiger Lizenzschlüssel – wird 10 Min. gecacht.');
    await redisSet(invalidCacheKey, 'invalid', INVALID_KEY_CACHE_SEC).catch(err =>
      console.error('[NEGATIVE CACHE] Schreiben fehlgeschlagen:', err)
    );
  }

  return { valid, fromCache: false };
}

// ══════════════════════════════════════════════════════════════════
// LS-AKTIVIERUNG: schaltet den Key im LS-Dashboard von "Inactive (0/1)"
// auf "Active (1/1)".
//
// WICHTIG: validate() allein aktiviert NICHTS – es prüft nur, ob der Key
// gültig ist. Erst ein erfolgreicher activate()-Call verbraucht einen
// "activation slot" und setzt den Status auf aktiv. Wir rufen das genau
// EINMAL auf – beim allerersten Request mit diesem Key (also exakt dann,
// wenn im KV noch kein "license:<key>"-Eintrag existiert, siehe Handler).
//
// instance_name ist Pflichtfeld bei LS und identifiziert dieses "Gerät"/
// diese Installation gegenüber dem Key (zählt gegen das Activation-Limit).
// Wir nutzen einen stabilen, nicht-personenbezogenen Bezeichner.
//
// Rückgabe: { activated, instanceId, licenseKeyId } – licenseKeyId wird
// im KV gespeichert, damit spätere GET /v1/license-keys/{id}-Calls (für
// den Top-Up-Recheck) ohne erneuten activate-Call möglich sind.
// ══════════════════════════════════════════════════════════════════
async function activateLicenseKey(licenseKey) {
  console.log('[LEMON SQUEEZY] Aktiviere Key...');
  const res = await fetch('https://api.lemonsqueezy.com/v1/licenses/activate', {
    method: 'POST',
    headers: {
      'Accept':       'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      license_key:   licenseKey,
      instance_name: 'focus-flashcards-app',
    }),
  });
  const data = await res.json().catch(() => ({}));

  // LS gibt bei bereits voll ausgeschöpftem Activation-Limit
  // { activated: false, error: "..." } zurück – das ist KEIN Fataler
  // Fehler für uns (der Key kann trotzdem gültig & nutzbar sein, z.B.
  // wenn der User den Key auf einem zweiten Gerät einträgt). Wir loggen
  // es nur und blockieren den Scan-Flow nicht deswegen.
  if (!data.activated) {
    console.warn('[LEMON SQUEEZY] Aktivierung nicht durchgeführt:', data.error || data);
    return { activated: false, instanceId: null, licenseKeyId: data.license_key?.id ?? null };
  }

  console.log(`[LEMON SQUEEZY] Key aktiviert. Instance: ${data.instance?.id}`);
  return {
    activated:    true,
    instanceId:   data.instance?.id ?? null,
    licenseKeyId: data.license_key?.id ?? null,
  };
}

// ══════════════════════════════════════════════════════════════════
// TOP-UP RE-CHECK: fragt den aktuellen Stand des Keys bei LS ab,
// bevor ein Scan wegen scansLeft<=0 final abgelehnt wird.
//
// Nutzt die AUTHENTIFIZIERTE REST-API (Bearer LEMONSQUEEZY_API_KEY),
// NICHT die License-API. Braucht die numerische licenseKeyId (im KV unter
// `license_id:<key>` gespeichert, siehe Handler).
//
// Top-Up-Erkennung:
//   Wir vergleichen das von LS gelieferte `attributes.activation_limit`
//   mit dem zuletzt bekannten Wert (`license_limit:<key>` im KV).
//   Ein Top-Up-Produkt in LS, das den Key per "increment activation limit"-
//   Webhook/Order erhöht, schlägt sich genau hier nieder. Steigt der Wert,
//   gutschreiben wir die Differenz * SCANS_PER_TOPUP_UNIT als neue Scans.
//
// HINWEIS: Falls dein Top-Up-Produkt in LS NICHT das activation_limit
// erhöht, sondern eine komplett neue Order ohne Limit-Änderung erzeugt,
// reicht ein reiner license-keys/{id}-GET nicht aus – dann braucht es
// zusätzlich einen LS-Webhook ("order_created") der die Order direkt dem
// Key zuordnet und das KV hochzählt. Dieser Re-Check hier ist der
// synchrone Fallback für den Fall, dass der Webhook (noch) nicht
// angekommen ist, wenn der User genau in diesem Moment scannt.
// ══════════════════════════════════════════════════════════════════
const SCANS_PER_TOPUP_UNIT = 200; // 1 zusätzlicher Activation-Slot = 200 Scans (anpassen an dein Produkt!)

async function getLicenseKeyDetails(licenseKeyId) {
  const lsApiKey = process.env.LEMONSQUEEZY_API_KEY;
  if (!lsApiKey) {
    console.warn('[LEMON SQUEEZY] LEMONSQUEEZY_API_KEY fehlt – Top-Up-Recheck wird übersprungen.');
    return null;
  }
  const res = await fetch(`https://api.lemonsqueezy.com/v1/license-keys/${licenseKeyId}`, {
    headers: {
      'Accept':        'application/vnd.api+json',
      'Authorization': `Bearer ${lsApiKey}`,
    },
  });
  if (!res.ok) {
    console.warn(`[LEMON SQUEEZY] license-keys/{id} fehlgeschlagen: ${res.status}`);
    return null;
  }
  const json = await res.json().catch(() => null);
  return json?.data?.attributes ?? null; // { status, activation_limit, activation_usage, ... }
}

// ══════════════════════════════════════════════════════════════════
// SECURITY FIX 1 – Race Condition (TOCTOU) beim Top-Up: Redis-Mutex
//
// SET NX (= "set if not exists") als Distributed Lock:
//   - Vor dem Check: Lock mit kurzer TTL setzen.
//   - Nur der Gewinner führt den Top-Up durch, Verlierer bekommen
//     sofort false (kein Blocking nötig).
//   - Lock wird im finally-Block immer freigegeben, auch bei Fehler.
// ══════════════════════════════════════════════════════════════════
async function acquireRedisLock(lockKey, ttlSeconds = 15) {
  const path = `/set/${encodeURIComponent(lockKey)}/1/NX/EX/${ttlSeconds}`;
  const json = await redisCall(path, 'POST');
  return json?.result === 'OK'; // true = Lock erworben, false = bereits vergeben
}

async function releaseRedisLock(lockKey) {
  await redisCall(`/del/${encodeURIComponent(lockKey)}`, 'POST').catch(err =>
    console.error('[MUTEX] Lock-Release fehlgeschlagen:', err)
  );
}

async function checkForTopUp(licenseKey) {
  const lockKey  = `lock:topup:${hashKey(licenseKey)}`;
  const acquired = await acquireRedisLock(lockKey, 15).catch(() => false);

  if (!acquired) {
    // Ein anderer Request führt gerade den Top-Up für denselben Key durch.
    // Kein Fehler – der parallele Request schreibt das korrekte Ergebnis,
    // der aufrufende Handler liest scansLeft danach neu aus dem KV.
    console.log('[MUTEX] Top-Up-Lock bereits vergeben, überspringe Recheck.');
    return false;
  }

  try {
    const licenseKeyId = await kvGet(`license_id:${licenseKey}`);
    if (!licenseKeyId) {
      console.log('[TOP-UP CHECK] Keine license_id im KV – Recheck übersprungen.');
      return false;
    }

    const attrs = await getLicenseKeyDetails(licenseKeyId);
    if (!attrs) return false;

    // Disabled/abgelaufene Keys dürfen niemals Scans gutgeschrieben bekommen,
    // auch wenn das activation_limit aus irgendeinem Grund hoch steht.
    if (attrs.status === 'disabled' || attrs.status === 'expired') {
      console.warn(`[TOP-UP CHECK] Key-Status "${attrs.status}" – kein Top-Up gewährt.`);
      return false;
    }

    const newLimit = Number(attrs.activation_limit);
    if (!Number.isFinite(newLimit)) return false;

    const knownLimitRaw = await kvGet(`license_limit:${licenseKey}`);
    const knownLimit    = knownLimitRaw !== null ? parseInt(knownLimitRaw, 10) : newLimit;

    if (newLimit > knownLimit) {
      const deltaUnits = newLimit - knownLimit;
      const bonusScans = deltaUnits * SCANS_PER_TOPUP_UNIT;

      console.log(`[TOP-UP CHECK] Limit-Anstieg erkannt: ${knownLimit} → ${newLimit}. Gutschrift: ${bonusScans} Scans.`);

      // WICHTIG: Reihenfolge ist jetzt atomar durch den Lock gesichert.
      // Kein paralleler Request kann zwischen diesen beiden Writes stören.
      await kvSet(`license_limit:${licenseKey}`, newLimit);
      await kvIncrBy(`license:${licenseKey}`, bonusScans);
      return true;
    }

    if (knownLimitRaw === null) {
      await kvSet(`license_limit:${licenseKey}`, newLimit);
    }
    return false;
  } catch (err) {
    console.error('[TOP-UP CHECK] Fehlgeschlagen:', err);
    return false;
  } finally {
    // Lock IMMER freigeben – auch bei Exception – damit keine Deadlocks
    // entstehen. Die 15s TTL ist das Fail-Safe, falls dieser Block aus
    // irgendeinem Grund nicht erreicht wird.
    await releaseRedisLock(lockKey);
  }
}

// ── Haupt-Handler ──────────────────────────────────────────────────────────
export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', 'https://focus-flashcards.app');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method Not Allowed' });

  // ════════════════════════════════════════════════════════════════
  // SECURITY: Globales IP-Rate-Limiting (vor allen anderen Checks)
  //
  // Schützt den gesamten Endpoint – unabhängig von Free-Trial/Paid/
  // Master-Key – vor Flooding/DoS durch eine einzelne IP. Nutzt denselben
  // atomaren INCR+EXPIRE(NX)-Pipeline-Mechanismus wie das restliche
  // Rate-Limiting (keine Race-Conditions möglich).
  // Max. 20 Requests/Minute pro IP.
  // ════════════════════════════════════════════════════════════════
  try {
    const globalIp        = getClientIp(req);
    const globalRateKey   = `rate:global_ip:${hashKey(globalIp)}`;
    const globalRateCount = await redisIncrWithTTL(globalRateKey, 60);

    console.log(`[GLOBAL RATE LIMIT] ${globalRateCount}/20 für IP-Hash`);

    if (globalRateCount > 20) {
      return res.status(429).json({
        error: 'Zu viele Anfragen. Bitte warte eine Minute und versuche es erneut.',
        retryAfter: 60,
      });
    }
  } catch (err) {
    // Fail-open: Wenn Redis nicht erreichbar ist, darf das globale
    // Rate-Limiting den gesamten Service nicht blockieren.
    console.error('[GLOBAL RATE LIMIT] Fehlgeschlagen, fahre fort:', err);
  }

  // OpenAI-Key prüfen
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'API-Key fehlt.' });

  // Authorization-Header auslesen
  const authHeader = req.headers['authorization'] || '';
  const licenseKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

  // Modus bestimmen
  // SECURITY: Defensive Master-Key-Prüfung.
  //   Problem ohne Boolean()-Guard:
  //     Wenn SECRET_MASTER_KEY nicht gesetzt ist, hat process.env.SECRET_MASTER_KEY
  //     den Wert `undefined`. licenseKey ist nach dem Trim() oben mindestens ''.
  //     '' === undefined → false  ✓ (zufällig korrekt, aber aus falschem Grund)
  //     Aber: Wenn die Variable auf einen Leerstring gesetzt wird (''),
  //     dann ist '' === '' → true → jeder Request ohne Auth-Header wird Master!
  //   Mit Boolean()-Guard: Boolean('') → false, Boolean(undefined) → false.
  //   Ein Master-Key-Match ist damit nur möglich wenn die Env-Variable
  //   existiert, nicht leer ist UND exakt mit dem gesendeten Key übereinstimmt.
  const isMasterKey   = Boolean(process.env.SECRET_MASTER_KEY) &&
                        licenseKey === process.env.SECRET_MASTER_KEY;
  const isFreeTrial   = !licenseKey || licenseKey === 'FREE_TRIAL';
  const isPaidLicense = !isMasterKey && !isFreeTrial;

  console.log(`[API START] Master: ${isMasterKey} | FreeTrial: ${isFreeTrial}`);

  // ════════════════════════════════════════════════════════════════
  // HONEYPOT: Bot-Schutz für Free-Tier-Zugriff
  //
  // Das Feld "trap" ist ein unsichtbares Input-Feld im Frontend.
  // Echte Nutzer sehen und füllen es nie aus (display:none + tabindex=-1).
  // Bots, die Formulare automatisch befüllen, füllen es typischerweise
  // mit Dummy-Werten aus → sofortige Ablehnung ohne OpenAI-Call.
  // ════════════════════════════════════════════════════════════════
  if (isFreeTrial) {
    const { trap } = req.body || {};
    if (trap && String(trap).trim().length > 0) {
      console.warn('[HONEYPOT] Bot erkannt – Anfrage abgelehnt.');
      // Absichtlich unspezifischer Fehler: kein Hinweis auf den Honeypot
      return res.status(400).json({ error: 'Ungültige Anfrage.' });
    }
  }

  // ════════════════════════════════════════════════════════════════
  // SECURITY: Blacklist-Check
  // ════════════════════════════════════════════════════════════════
  if (!isMasterKey) {
    try {
      const identifier    = isFreeTrial ? getClientIp(req) : licenseKey;
      const hashedId      = hashKey(identifier);
      const blacklistKey  = `blacklist:${hashedId}`;
      const isBanned      = await redisExists(blacklistKey);

      if (isBanned) {
        console.warn(`[SECURITY] Gesperrter Identifier versucht Zugriff (Hash: ${hashedId.slice(0, 8)}...)`);
        return res.status(403).json({
          error:   'Dein Zugang wurde temporär gesperrt. Bitte versuche es später erneut oder kontaktiere den Support.',
          cooldown: true,
        });
      }
    } catch (err) {
      console.error('[SECURITY] Blacklist-Check fehlgeschlagen:', err);
    }
  }

  let usageCurrent   = null;
  let remainingScans = null;
  let creditDeducted = false; // true sobald Pre-Deduction stattgefunden hat (für Refund/Outer-Catch)

  try {

    // ════════════════════════════════════════════════════════════════
    // A) FREE TRIAL – Atomares IP-Throttling via Redis Pipeline
    //
    // INCR und EXPIRE werden in einem einzigen atomaren Pipeline-Call
    // ausgeführt. Das verhindert Race-Conditions bei gleichzeitigen
    // Requests von derselben IP:
    //   - Ohne Pipeline: INCR→1, crash vor EXPIRE → Key läuft nie ab
    //   - Mit Pipeline:  INCR+EXPIRE(NX) atomar → TTL immer gesetzt
    //
    // EXPIRE NX = nur setzen wenn noch keine TTL existiert
    //   → Die 24h laufen ab dem ersten Request dieser IP, nicht ab
    //     jedem weiteren Request (kein "Rolling Window").
    // ════════════════════════════════════════════════════════════════
    if (isFreeTrial) {
      const ip       = getClientIp(req);
      const redisKey = `free_trial_ip:${hashKey(ip)}`;
      const count    = await redisIncrWithTTL(redisKey, FREE_TRIAL_TTL_SEC);

      console.log(`[FREE TRIAL] Zähler: ${count}/${FREE_TRIAL_LIMIT}`);

      if (count > FREE_TRIAL_LIMIT) {
        return res.status(429).json({ error: 'LIMIT_REACHED' });
      }
      usageCurrent = count;
    }

    // ── Bild aus Request-Body holen (VOR jeder Pre-Deduction!) ─────
    // Muss vor dem Credit-Abzug passieren, damit ungültige Requests
    // (kein Bild übermittelt) keine Credits kosten.
    const { image } = req.body || {};
    if (!image || typeof image !== 'string') {
      return res.status(400).json({ error: 'Kein Bild übermittelt.' });
    }
    const base64Data = image.includes(',') ? image.split(',')[1] : image;

    // ════════════════════════════════════════════════════════════════
    // SECURITY FIX 4: Bild validieren BEVOR Credits abgezogen oder
    // OpenAI kontaktiert wird (Größe + Magic-Bytes-Format-Check).
    // ════════════════════════════════════════════════════════════════
    const imageValidation = validateBase64Image(base64Data);
    if (!imageValidation.valid) {
      console.warn('[VALIDATION] Ungültiges Bild:', imageValidation.reason);
      return res.status(400).json({ error: imageValidation.reason });
    }

    // ════════════════════════════════════════════════════════════════
    // B) PAID LICENSE – Lemon Squeezy + KV Scan-Konto
    //    Negative Caching ist jetzt in validateLemonSqueezy() integriert.
    // ════════════════════════════════════════════════════════════════
    if (isPaidLicense) {
      // ── Rate-Limiting: max. 5 Scans/Minute pro Lizenzschlüssel ────
      // Verhindert, dass ein einzelner Paid-Key durch Skript-Flooding
      // das globale OpenAI-Rate-Limit für alle Nutzer auslöst.
      // Verwendet denselben atomaren INCR+EXPIRE(NX)-Pipeline-Mechanismus
      // wie das Free-Trial-Throttling (keine Race-Conditions möglich).
      const rateLimitKey   = `rate:license:${licenseKey}`;
      const rateLimitCount = await redisIncrWithTTL(rateLimitKey, 60);
      console.log(`[RATE LIMIT] Lizenz-Scans diese Minute: ${rateLimitCount}/5`);
      if (rateLimitCount > 5) {
        return res.status(429).json({
          error: 'Zu viele Anfragen. Bitte warte eine Minute und versuche es erneut.',
          retryAfter: 60,
        });
      }
    }

    if (isPaidLicense) {
      if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
        return res.status(500).json({ error: 'Datenbank-Konfigurationsfehler.' });
      }

      const raw     = await kvGet(`license:${licenseKey}`);
      let scansLeft = raw !== null ? parseInt(raw, 10) : null;

      console.log(`[KV GET] Scans verbleibend: ${scansLeft}`);

      if (scansLeft === null || isNaN(scansLeft)) {
        // ────────────────────────────────────────────────────────────
        // SECURITY FIX 5: Failed-Auth-Rate-Limit prüfen BEVOR Negative-
        // Cache oder die LS-API kontaktiert werden. Verhindert, dass ein
        // Angreifer durch endloses Senden neuer, nie zuvor gesehener
        // Strings die LS-API floodet (jeder verfehlt den Negative-Cache).
        // ────────────────────────────────────────────────────────────
        const clientIp           = getClientIp(req);
        const isFailedAuthBlocked = await checkInvalidKeyRateLimit(clientIp).catch(() => false);
        if (isFailedAuthBlocked) {
          console.warn('[FAILED AUTH] IP hat zu viele ungültige Keys gesendet – Block ohne LS-Call.');
          return res.status(429).json({
            error: 'Zu viele fehlgeschlagene Versuche. Bitte warte 15 Minuten.',
            retryAfter: INVALID_KEY_WINDOW_SEC,
          });
        }

        // validateLemonSqueezy() prüft Negative-Cache intern,
        // ruft LS-API nur wenn nötig, und schreibt bei Fehler in Cache.
        const { valid, fromCache } = await validateLemonSqueezy(licenseKey);

        if (!valid) {
          // FIX 5: Fehlversuch zählen (darf die Response nicht verzögern,
          // aber muss vor dem return awaited werden, da Vercel den Container
          // sofort nach der Response einfriert – siehe Kommentar bei redisLog).
          await recordInvalidKeyAttempt(clientIp).catch(() => {});

          const reason = fromCache ? 'aus Cache' : 'von LS-API';
          console.warn(`[BLOCKIERT] Ungültiger Lizenzschlüssel (${reason}).`);
          return res.status(403).json({ error: 'Ungültiger oder abgelaufener Lizenzschlüssel.' });
        }

        // ────────────────────────────────────────────────────────────
        // LS-AKTIVIERUNG: nur beim allerersten validen Aufruf mit
        // diesem Key (also genau jetzt, wo noch kein KV-Eintrag
        // existiert). Setzt den Status im LS-Dashboard auf "Active".
        // Ein Fehlschlag hier blockiert den Scan-Flow NICHT (fail-open) –
        // der Key wurde von validateLemonSqueezy() bereits als gültig
        // bestätigt, ein Aktivierungsproblem ist ein reines LS-Dashboard-
        // Anzeigeproblem, kein Sicherheitsproblem.
        let licenseKeyId = null;
        try {
          const activation = await activateLicenseKey(licenseKey);
          licenseKeyId = activation.licenseKeyId;
          if (licenseKeyId) {
            await kvSet(`license_id:${licenseKey}`, licenseKeyId);
          }
        } catch (err) {
          console.error('[LEMON SQUEEZY] Aktivierung fehlgeschlagen, fahre fort:', err);
        }

        scansLeft = 200;
        await kvSet(`license:${licenseKey}`, scansLeft);
        // Baseline für den Top-Up-Recheck setzen (falls Details verfügbar sind).
        if (licenseKeyId) {
          const attrs = await getLicenseKeyDetails(licenseKeyId).catch(() => null);
          if (attrs && Number.isFinite(Number(attrs.activation_limit))) {
            await kvSet(`license_limit:${licenseKey}`, Number(attrs.activation_limit));
          }
        }
        console.log('[KV SET] 200 Scans angelegt.');
      }

      if (scansLeft <= 0) {
        // ────────────────────────────────────────────────────────────
        // TOP-UP RE-CHECK: bevor wir final ablehnen, fragen wir LS,
        // ob sich das activation_limit erhöht hat (= Top-Up gekauft).
        // Bei Erfolg wird das KV direkt gutgeschrieben und scansLeft
        // neu gelesen.
        // ────────────────────────────────────────────────────────────
        const toppedUp = await checkForTopUp(licenseKey);
        if (toppedUp) {
          const refreshed = await kvGet(`license:${licenseKey}`);
          scansLeft = refreshed !== null ? parseInt(refreshed, 10) : 0;
          console.log(`[TOP-UP CHECK] Scans nach Gutschrift: ${scansLeft}`);
        }
      }

      if (scansLeft <= 0) {
        console.warn('[BLOCKIERT] Keine Scans mehr verfügbar.');
        return res.status(402).json({ error: 'Deine Scans sind aufgebraucht.' });
      }

      // ════════════════════════════════════════════════════════════
      // SECURITY: Pre-Deduction (Race-Condition-Fix)
      //
      // Vorher wurde der Credit erst NACH einem erfolgreichen OpenAI-
      // Call abgezogen (kvDecr ganz am Ende). Problem: Zwischen dem
      // scansLeft-Check oben und dem späten kvDecr konnten mehrere
      // parallele Requests denselben "letzten" Credit durchwinken,
      // bevor einer von ihnen den Zähler tatsächlich verringert hat
      // → mehr OpenAI-Calls als bezahlte Credits.
      //
      // Fix: Credit wird HIER, sofort nach dem Check und VOR dem
      // teuren OpenAI-Call, atomar via KV DECR abgezogen. Schlägt der
      // OpenAI-Call danach fehl (Timeout/Error/Content-Policy/Parse-
      // Fehler), wird der Credit über refundIfPaidLicense() sofort
      // wieder gutgeschrieben.
      // ════════════════════════════════════════════════════════════
      remainingScans  = await kvDecr(`license:${licenseKey}`);
      creditDeducted  = true;
      console.log(`[KV DECR - PRE] Credit vorab abgezogen. Verbleibend: ${remainingScans}`);
    }

    // ── OpenAI Vision aufrufen ─────────────────────────────────────
    console.log('[OPENAI] Sende Bild...');

    // AbortController: internes Timeout von 30 s.
    // Vercel Hobby-Tier bricht Serverless-Funktionen nach 30  s hart ab –
    // wir fangen einen Hänger bei OpenAI kontrolliert ab und senden dem
    // Client eine saubere JSON-Antwort statt eines hässlichen 504/FUNCTION_INVOCATION_TIMEOUT.
    const abortController = new AbortController();
    const openAITimeout   = setTimeout(() => abortController.abort(), 300000);

    let openAIResponse;
    try {
      openAIResponse = await fetch('https://api.openai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization:  `Bearer ${apiKey}`,
        },
        signal: abortController.signal,
        body: JSON.stringify({
          model:           'gpt-4o-mini',
          max_tokens:      8192,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: SYSTEM_PROMPT },
            {
              role: 'user',
              content: [
                {
                  type:      'image_url',
                  image_url: { url: `data:image/jpeg;base64,${base64Data}`, detail: 'high' },
                },
                { type: 'text', text: 'Extrahiere die wichtigsten Konzepte oder Vokabelpaare aus diesem Bild und antworte im geforderten JSON-Format.' },
              ],
            },
          ],
        }),
      });
    } catch (fetchErr) {
      if (fetchErr.name === 'AbortError') {
        console.warn('[OPENAI TIMEOUT] Request nach 30 s abgebrochen.');
        await refundIfPaidLicense(isPaidLicense, licenseKey);
        creditDeducted = false;
        return res.status(504).json({
          error: 'Die KI antwortet aktuell zu langsam, bitte versuche es noch einmal.',
          timeout: true,
        });
      }
      await refundIfPaidLicense(isPaidLicense, licenseKey);
      creditDeducted = false; // bereits zurückerstattet → Outer-Catch darf nicht erneut gutschreiben
      throw fetchErr; // unerwarteter Netzwerkfehler → outer catch (KEIN doppelter Refund)
    } finally {
      clearTimeout(openAITimeout);
    }

    // ════════════════════════════════════════════════════════════════
    // SECURITY: OpenAI Content-Policy-Fehler → temporärer Cooldown
    // ════════════════════════════════════════════════════════════════
    if (!openAIResponse.ok) {
      const errBody = await openAIResponse.json().catch(() => ({}));
      const errCode = errBody?.error?.code    || '';
      const errMsg  = errBody?.error?.message || '';

      if (
        openAIResponse.status === 400 &&
        (errCode === 'content_policy_violation' || errMsg.toLowerCase().includes('policy'))
      ) {
        const identifier   = isFreeTrial ? getClientIp(req) : licenseKey;
        const hashedId     = hashKey(identifier);
        const blacklistKey = `blacklist:${hashedId}`;

        await redisSet(blacklistKey, 'policy_cooldown', POLICY_COOLDOWN_SEC).catch(() => {});
        // await statt fire-and-forget: Log muss committed sein bevor Vercel
        // den Container nach dem return einfriert (siehe Kommentar in redisLog).
        await redisLog('OPENAI_POLICY_VIOLATION', hashedId);

        console.warn(`[SECURITY] Content-Policy-Verletzung – 15-Min-Cooldown gesetzt (Hash: ${hashedId.slice(0, 8)}...)`);

        await refundIfPaidLicense(isPaidLicense, licenseKey);
        creditDeducted = false;

        // Erweitertes Fehler-Objekt:
        //   • code        – maschinenlesbar für programmatische Frontend-Logik
        //   • ui_message  – direkt in Banner-State setzbar, kein i18n-Mapping nötig
        //   • cooldown    – Signal für den Retry-Timer im Frontend
        //   • error       – Legacy-Feld (bleibt für Abwärtskompatibilität)
        return res.status(403).json({
          error:      'CONTENT_POLICY_VIOLATION',
          code:       'CONTENT_POLICY_VIOLATION',
          cooldown:   true,
          ui_message: CONTENT_POLICY_MESSAGES,
        });
      }

      await refundIfPaidLicense(isPaidLicense, licenseKey);
      creditDeducted = false;
      return res.status(502).json({ error: `OpenAI API Fehler: ${openAIResponse.status}` });
    }

    const openAIData = await openAIResponse.json();
    const rawContent = openAIData.choices?.[0]?.message?.content || '{}';

    // ── JSON parsen ────────────────────────────────────────────────
    let pairs;
    try {
      const parsedData = JSON.parse(rawContent);
      pairs = parsedData.flashcards;
      if (!Array.isArray(pairs)) {
        throw new Error('Fehlendes Array im "flashcards" Schlüssel');
      }
    } catch (parseError) {
      console.error('[PARSE ERROR]', parseError, 'Raw Content:', rawContent);
      await refundIfPaidLicense(isPaidLicense, licenseKey);
      creditDeducted = false;
      return res.status(422).json({ error: 'Ungültiges JSON vom AI-Modell.' });
    }

    // ── Scan wurde bereits VOR dem OpenAI-Call abgezogen (Pre-Deduction) ───
    // Kein erneuter kvDecr hier nötig – remainingScans wurde bereits oben
    // beim Pre-Deduction-Schritt gesetzt.

    // ── Erfolg-Response ────────────────────────────────────────────
    console.log('[API SUCCESS]');

    const responsePayload = { pairs };

    if (usageCurrent !== null) {
      responsePayload.usage = { current: usageCurrent, limit: FREE_TRIAL_LIMIT };
    }
    if (remainingScans !== null) {
      responsePayload.remaining_scans = remainingScans;
    }

    return res.status(200).json(responsePayload);

  } catch (err) {
    console.error('[FATAL ERROR]', err);
    // Falls der Credit bereits per Pre-Deduction abgezogen wurde und der
    // Fehler nicht über einen der spezifischen Fehlerpfade oben behandelt
    // (und dort schon refunded) wurde, hier nachträglich gutschreiben.
    if (creditDeducted) {
      await refundIfPaidLicense(isPaidLicense, licenseKey);
    }
    return res.status(500).json({ error: 'Interner Serverfehler.' });
  }
}
