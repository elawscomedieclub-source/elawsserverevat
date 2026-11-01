const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    },
    pingTimeout: 60000,
    pingInterval: 25000
});

/**
 * Map téléphone → {
 *   nom, metier, socketId, lastSeen, online,
 *   recoveryPinHash, createdAt, lastDevice
 * }
 * Un numéro = UN seul compte. Récupération uniquement avec le code secret.
 */
const registeredUsers = new Map();

const messageHistory = [];
const MAX_HISTORY = 200;

// Noms d'exemple interdits
const NOMS_INTERDITS = [
    'kodjo marceline',
    'kodjo',
    'marceline',
    'test',
    'admin',
    'utilisateur',
    'user',
    'exemple',
    'demo',
    'opérateur',
    'operateur'
];

function nettoyerTel(tel) {
    if (!tel) return '';
    return String(tel).replace(/[\s\-\.\(\)]/g, '').trim();
}

function hashPin(pin) {
    return crypto.createHash('sha256').update(String(pin).trim()).digest('hex');
}

function genererPin() {
    // Code à 6 chiffres, facile à noter, difficile à deviner
    return String(Math.floor(100000 + Math.random() * 900000));
}

function nomEstValide(nom) {
    if (!nom || typeof nom !== 'string') return false;
    const n = nom.trim().toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    if (n.length < 3) return false;
    if (NOMS_INTERDITS.some(interdit => n === interdit || n.includes(interdit))) return false;
    // Au moins une lettre
    if (!/[a-zàâäéèêëïîôùûüç]/i.test(nom)) return false;
    return true;
}

function telEstValide(tel) {
    const t = nettoyerTel(tel);
    // Doit commencer par + et avoir entre 10 et 16 caractères au total
    if (!/^\+[1-9]\d{8,14}$/.test(t)) return false;
    return true;
}

function getOnlineUsers() {
    const list = [];
    for (const [tel, u] of registeredUsers.entries()) {
        if (u.online) {
            list.push({
                telephone: tel,
                nom: u.nom,
                metier: u.metier,
                lastSeen: u.lastSeen
            });
        }
    }
    return list;
}

io.on('connection', (socket) => {
    console.log(`[+] Connexion : ${socket.id}`);

    // Vérifier si un numéro est déjà pris (sans révéler le nom complet)
    socket.on('check_phone', (data, callback) => {
        const cleanTel = nettoyerTel(data && data.telephone);
        if (!telEstValide(cleanTel)) {
            if (typeof callback === 'function') {
                callback({ ok: false, error: 'Numéro invalide. Format attendu : +228XXXXXXXX' });
            }
            return;
        }
        const exists = registeredUsers.has(cleanTel);
        if (typeof callback === 'function') {
            callback({
                ok: true,
                exists,
                // On ne révèle PAS le nom : juste si le compte existe
                message: exists
                    ? 'Ce numéro est déjà enregistré. Entrez votre code de récupération pour récupérer le compte.'
                    : 'Numéro disponible. Vous pouvez créer un nouveau compte.'
            });
        }
    });

    /**
     * Création d'un NOUVEAU compte
     * data: { nom, telephone, metier }
     * → génère un recoveryPin unique, renvoyé UNE SEULE FOIS
     */
    socket.on('register_new', (data, callback) => {
        if (!data || !data.telephone || !data.nom) {
            if (typeof callback === 'function') callback({ ok: false, error: 'Nom et téléphone obligatoires.' });
            return;
        }

        const cleanTel = nettoyerTel(data.telephone);
        const nom = String(data.nom).trim();
        const metier = String(data.metier || 'Opérateur').trim().slice(0, 80);

        if (!telEstValide(cleanTel)) {
            if (typeof callback === 'function') callback({ ok: false, error: 'Numéro invalide. Exemple : +22890123456' });
            return;
        }
        if (!nomEstValide(nom)) {
            if (typeof callback === 'function') {
                callback({
                    ok: false,
                    error: 'Nom invalide ou réservé (exemples / tests interdits). Entrez VOTRE vrai nom et prénom.'
                });
            }
            return;
        }

        if (registeredUsers.has(cleanTel)) {
            if (typeof callback === 'function') {
                callback({
                    ok: false,
                    error: 'Ce numéro est déjà lié à un compte. Utilisez « Récupérer mon compte » avec votre code secret.',
                    needsRecovery: true
                });
            }
            return;
        }

        const pin = genererPin();
        const pinHash = hashPin(pin);

        registeredUsers.set(cleanTel, {
            nom,
            metier,
            socketId: socket.id,
            online: true,
            lastSeen: Date.now(),
            recoveryPinHash: pinHash,
            createdAt: Date.now(),
            lastDevice: socket.id
        });

        socket.telephone = cleanTel;
        console.log(`[NEW] Compte créé : ${nom} (${cleanTel})`);

        socket.broadcast.emit('contact_registered', {
            nom,
            telephone: cleanTel,
            metier
        });
        io.emit('presence_update', getOnlineUsers());

        if (typeof callback === 'function') {
            callback({
                ok: true,
                recoveryPin: pin, // UNIQUEMENT à la création — à noter obligatoirement
                message: 'Compte créé. Notez bien votre code de récupération : vous en aurez besoin si vous changez de téléphone.'
            });
        }
    });

    /**
     * Récupération d'un compte existant (changement de téléphone / nouvel appareil)
     * data: { telephone, recoveryPin, nom? }
     * Le PIN prouve que c'est bien le propriétaire.
     */
    socket.on('recover_account', (data, callback) => {
        if (!data || !data.telephone || !data.recoveryPin) {
            if (typeof callback === 'function') callback({ ok: false, error: 'Numéro et code de récupération obligatoires.' });
            return;
        }

        const cleanTel = nettoyerTel(data.telephone);
        const pin = String(data.recoveryPin).trim();

        if (!registeredUsers.has(cleanTel)) {
            if (typeof callback === 'function') callback({ ok: false, error: 'Aucun compte trouvé pour ce numéro.' });
            return;
        }

        const user = registeredUsers.get(cleanTel);
        if (user.recoveryPinHash !== hashPin(pin)) {
            console.log(`[RECOVER FAIL] Mauvais PIN pour ${cleanTel}`);
            if (typeof callback === 'function') callback({ ok: false, error: 'Code de récupération incorrect.' });
            return;
        }

        // Déconnecter l'ANCIEN appareil automatiquement
        const oldSocketId = user.socketId;
        if (oldSocketId && oldSocketId !== socket.id) {
            const oldSocket = io.sockets.sockets.get(oldSocketId);
            if (oldSocket) {
                oldSocket.emit('force_logout', {
                    reason: 'session_taken',
                    message: 'Votre compte a été ouvert sur un autre appareil. Vous avez été déconnecté automatiquement.'
                });
                oldSocket.telephone = null;
                console.log(`[FORCE LOGOUT] Ancien appareil ${oldSocketId} déconnecté pour ${cleanTel}`);
            }
        }

        // Nouveau code d'activation : l'ancien PIN devient invalide
        const nouveauPin = genererPin();
        user.recoveryPinHash = hashPin(nouveauPin);
        user.socketId = socket.id;
        user.online = true;
        user.lastSeen = Date.now();
        user.lastDevice = socket.id;
        if (data.metier && String(data.metier).trim()) {
            user.metier = String(data.metier).trim().slice(0, 80);
        }
        registeredUsers.set(cleanTel, user);
        socket.telephone = cleanTel;

        console.log(`[RECOVER OK] ${user.nom} (${cleanTel}) → nouvel appareil ${socket.id} + nouveau PIN`);

        io.emit('presence_update', getOnlineUsers());

        if (typeof callback === 'function') {
            callback({
                ok: true,
                recoveryPin: nouveauPin,
                profil: {
                    nom: user.nom,
                    telephone: cleanTel,
                    metier: user.metier
                },
                message: 'Compte récupéré. Ancien appareil déconnecté. Notez votre NOUVEAU code de récupération.'
            });
        }
    });

    /**
     * Connexion d'une session déjà connue localement (localStorage)
     * data: { telephone, recoveryPin } — on vérifie le PIN pour éviter l'usurpation
     */
    socket.on('register_user', (data, callback) => {
        if (!data || !data.telephone) {
            if (typeof callback === 'function') callback && callback({ ok: false, error: 'Téléphone manquant.' });
            return;
        }

        const cleanTel = nettoyerTel(data.telephone);
        const existing = registeredUsers.get(cleanTel);

        // Si le compte existe côté serveur, on exige le PIN
        if (existing) {
            if (data.recoveryPin && existing.recoveryPinHash === hashPin(data.recoveryPin)) {
                // Déconnecter l'ancien appareil si c'est un autre socket
                const oldSocketId = existing.socketId;
                if (oldSocketId && oldSocketId !== socket.id) {
                    const oldSocket = io.sockets.sockets.get(oldSocketId);
                    if (oldSocket) {
                        oldSocket.emit('force_logout', {
                            reason: 'session_taken',
                            message: 'Votre compte a été ouvert sur un autre appareil. Vous avez été déconnecté automatiquement.'
                        });
                        oldSocket.telephone = null;
                        console.log(`[FORCE LOGOUT] Ancien appareil ${oldSocketId} déconnecté pour ${cleanTel}`);
                    }
                }
                existing.socketId = socket.id;
                existing.online = true;
                existing.lastSeen = Date.now();
                existing.lastDevice = socket.id;
                registeredUsers.set(cleanTel, existing);
                socket.telephone = cleanTel;
                io.emit('presence_update', getOnlineUsers());
                if (typeof callback === 'function') callback({ ok: true });
                return;
            }
            // Sans PIN valide : on ne prend PAS le contrôle du compte
            if (typeof callback === 'function') {
                callback({
                    ok: false,
                    error: 'Ce numéro appartient déjà à un compte. Utilisez le code de récupération.',
                    needsRecovery: true
                });
            }
            return;
        }

        // Compte pas encore côté serveur (redémarrage serveur) mais client a un profil local
        // On recrée le compte UNIQUEMENT si un PIN est fourni (sinon on refuse pour éviter le vol)
        if (data.recoveryPin && nomEstValide(data.nom) && telEstValide(cleanTel)) {
            registeredUsers.set(cleanTel, {
                nom: String(data.nom).trim(),
                metier: String(data.metier || 'Opérateur').trim(),
                socketId: socket.id,
                online: true,
                lastSeen: Date.now(),
                recoveryPinHash: hashPin(data.recoveryPin),
                createdAt: Date.now(),
                lastDevice: socket.id
            });
            socket.telephone = cleanTel;
            io.emit('presence_update', getOnlineUsers());
            if (typeof callback === 'function') callback({ ok: true, restored: true });
            return;
        }

        if (typeof callback === 'function') {
            callback({ ok: false, error: 'Impossible de lier ce numéro sans code de récupération.' });
        }
    });

    // Demande de contacts
    socket.on('query_contacts', (telephones, callback) => {
        const resultats = [];
        if (Array.isArray(telephones)) {
            telephones.forEach(tel => {
                const cleanTel = nettoyerTel(tel);
                if (registeredUsers.has(cleanTel)) {
                    const usr = registeredUsers.get(cleanTel);
                    resultats.push({
                        telephone: cleanTel,
                        metier: usr.metier,
                        nom: usr.nom,
                        online: !!usr.online,
                        lastSeen: usr.lastSeen
                    });
                }
            });
        }
        if (typeof callback === 'function') callback(resultats);
    });

    // Signalisation WebRTC
    socket.on('p2p_signal', (data) => {
        if (!data || !data.target) return;
        const cleanTarget = nettoyerTel(data.target);
        const targetUser = registeredUsers.get(cleanTarget);

        if (targetUser && targetUser.socketId && targetUser.online) {
            io.to(targetUser.socketId).emit('p2p_signal', data);
        } else {
            socket.emit('p2p_signal', {
                type: 'user_offline',
                target: cleanTarget,
                sender: data.sender
            });
        }
    });

    // Messagerie
    socket.on('send_message', (payload) => {
        if (!payload || !payload.texte) return;

        const msg = {
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
            from: payload.from || socket.telephone,
            fromName: payload.fromName || 'Inconnu',
            to: payload.to || null,
            texte: String(payload.texte).slice(0, 1000),
            heure: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }),
            timestamp: Date.now()
        };

        messageHistory.push(msg);
        if (messageHistory.length > MAX_HISTORY) messageHistory.shift();

        if (msg.to) {
            const target = registeredUsers.get(nettoyerTel(msg.to));
            if (target && target.socketId) {
                io.to(target.socketId).emit('new_message', msg);
            }
            socket.emit('new_message', msg);
        } else {
            io.emit('new_message', msg);
        }
    });

    socket.on('get_history', (limit, callback) => {
        const n = Math.min(parseInt(limit) || 50, 100);
        const recent = messageHistory.slice(-n);
        if (typeof callback === 'function') callback(recent);
    });

    socket.on('signal', (data) => {
        if (data && data.type === 'location') {
            socket.broadcast.emit('signal', { ...data, senderTel: socket.telephone });
        } else {
            socket.broadcast.emit('signal', data);
        }
    });

    socket.on('heartbeat', () => {
        if (socket.telephone && registeredUsers.has(socket.telephone)) {
            const u = registeredUsers.get(socket.telephone);
            u.lastSeen = Date.now();
            u.online = true;
            registeredUsers.set(socket.telephone, u);
        }
    });

    socket.on('disconnect', () => {
        console.log(`[-] Déconnexion : ${socket.id}`);
        if (socket.telephone && registeredUsers.has(socket.telephone)) {
            const u = registeredUsers.get(socket.telephone);
            u.online = false;
            u.lastSeen = Date.now();
            registeredUsers.set(socket.telephone, u);
        }
        io.emit('presence_update', getOnlineUsers());
    });
});

app.get('/', (req, res) => {
    res.json({
        status: 'EVAT Continuum Signaling Server (sécurisé)',
        online: registeredUsers.size,
        messages: messageHistory.length,
        time: new Date().toISOString()
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Serveur EVAT Continuum (sécurisé) actif sur le port ${PORT}`);
});
