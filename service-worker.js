const CACHE_NAME = 'lollys-collection-cache-v1';
const urlsToCache = [
    '/',
    '/index.html',
    '/products',
    '/cart',
    '/about',
    '/contact',
    '/auth',
    '/profile.html',
    '/manifest.json',
    // --- CSS & Fonts ---
    'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css',
    // --- Icons (Ensure these paths exist) ---
    '/images/icons/favicon-32x32.png',
    '/images/icons/apple-touch-icon.png',
    '/images/icons/icon-192x192.png',
    '/images/icons/icon-512x512.png',
    '/images/icons/maskable_icon.png'
];

// Install event: cache all necessary assets
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => {
                console.log('Opened cache');
                return cache.addAll(urlsToCache);
            })
    );
});

// Fetch event: serve content from cache first, then network
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                // Cache hit - return response
                if (response) {
                    return response;
                }
                // No cache hit - fetch from network
                return fetch(event.request);
            })
    );
});

// Activate event: clear old caches
self.addEventListener('activate', event => {
    const cacheWhitelist = [CACHE_NAME];
    event.waitUntil(
        caches.keys().then(cacheNames => {
            return Promise.all(
                cacheNames.map(cacheName => {
                    if (cacheWhitelist.indexOf(cacheName) === -1) {
                        return caches.delete(cacheName);
                    }
                })
            );
        })
    );
});