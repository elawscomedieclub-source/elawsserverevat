/* EVAT Continuum — Service Worker v4.1
   - Coquille de l'app précachée (démarrage instantané + hors ligne)
   - Fichiers de l'app : "stale-while-revalidate" (rapide, mis à jour en arrière-plan)
   - Socket.io / API / tuiles de carte : jamais interceptés (aucun risque de casser le temps réel)
   - Bibliothèques CDN : mises en cache à la première utilisation */
const VERSION = 'evat-continuum-v410';
const SHELL = `${VERSION}-shell`;
const RUNTIME = `${VERSION}-runtime`;

const ASSETS = [
    './',
    './index.html',
    './app.js',
    './style.css',
    './logo_evat.svg',
    './icon-192.png',
    './icon-512.png',
    './apple-touch-icon.png',
    './manifest.webmanifest'
];

const CDN_OK = ['cdn.socket.io', 'unpkg.com'];

self.addEventListener('install', (e) => {
    e.waitUntil(
        caches.open(SHELL)
            // addAll échoue si un seul fichier manque : on les ajoute un par un
            .then(cache => Promise.all(ASSETS.map(a => cache.add(a).catch(() => {}))))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (e) => {
    e.waitUntil(
        caches.keys()
            .then(keys => Promise.all(keys.filter(k => !k.startsWith(VERSION)).map(k => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (e) => {
    const req = e.request;
    if (req.method !== 'GET') return;

    const url = new URL(req.url);

    // Temps réel, serveur, tuiles OSM : on laisse passer sans toucher
    if (url.pathname.includes('/socket.io/') ||
        url.hostname.endsWith('onrender.com') ||
        url.hostname.endsWith('tile.openstreetmap.org')) return;

    // Navigation : réseau d'abord, repli sur la page en cache (hors ligne)
    if (req.mode === 'navigate') {
        e.respondWith(
            fetch(req).catch(() => caches.match('./index.html'))
        );
        return;
    }

    // Fichiers de l'app et bibliothèques CDN : stale-while-revalidate
    const memeOrigine = url.origin === self.location.origin;
    if (memeOrigine || CDN_OK.includes(url.hostname)) {
        e.respondWith(
            caches.match(req).then(cached => {
                const reseau = fetch(req).then(res => {
                    if (res && (res.ok || res.type === 'opaque')) {
                        const copie = res.clone();
                        caches.open(memeOrigine ? SHELL : RUNTIME).then(c => c.put(req, copie));
                    }
                    return res;
                }).catch(() => cached);
                return cached || reseau;
            })
        );
    }
});

/* ---------- Notifications push (appel / message / appel manqué) — fonctionne app fermée ---------- */
self.addEventListener('push', (e) => {
    let d = {};
    try { d = e.data ? e.data.json() : {}; } catch (err) { d = { title: 'EVAT', body: e.data ? e.data.text() : '' }; }

    e.waitUntil((async () => {
        // Si l'app est déjà affichée à l'écran, elle gère elle-même l'alerte (sonnerie, bannière)
        const fenetres = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        if (fenetres.some(c => c.visibilityState === 'visible')) return;

        const appel = d.type === 'call';
        await self.registration.showNotification(d.title || 'EVAT', {
            body: d.body || '',
            tag: d.tag || 'evat',
            renotify: true,
            icon: 'icon-192.png',
            badge: 'icon-192.png',
            requireInteraction: appel,                       // l'appel reste affiché jusqu'à action
            vibrate: appel ? [600, 250, 600, 250, 600, 250, 600] : [200, 100, 200],
            silent: false,
            timestamp: Date.now(),
            data: { type: d.type, from: d.from, callId: d.callId },
            actions: appel ? [{ action: 'accept', title: '🟢 Répondre' }] : []
        });

        // Un appel ne dure que ~30 s : on retire la notification périmée
        if (appel) {
            setTimeout(async () => {
                const l = await self.registration.getNotifications({ tag: d.tag || 'evat' });
                l.forEach(n => n.close());
            }, 35000);
        }
    })());
});

// Toucher la notification : ramène l'app au premier plan et ouvre la bonne conversation / l'appel
self.addEventListener('notificationclick', (e) => {
    const data = e.notification.data || {};
    const action = e.action || '';
    e.notification.close();
    e.waitUntil((async () => {
        const liste = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        for (const c of liste) {
            if ('focus' in c) {
                await c.focus();
                c.postMessage({ type: 'notif-click', data, action });
                return;
            }
        }
        const url = './index.html?open=' + encodeURIComponent(data.type || '') +
                    '&from=' + encodeURIComponent(data.from || '') +
                    (action === 'accept' ? '&accept=1' : '');
        await self.clients.openWindow(url);
    })());
});
