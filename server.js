
const http = require('http');
const { Server } = require('socket.io');

const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('EVAT Quantum Signalisation Server v3.60 Turbo is running.\n');
});

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

io.on('connection', (socket) => {
    console.log(`Nouvel utilisateur connecté : ${socket.id}`);

    // Gestion du relais de signalisation WebRTC (Offres / Réponses / Candidates ICE)
    socket.on('signal_offer', (data) => {
        socket.broadcast.emit('signal_offer', data);
    });

    socket.on('signal_answer', (data) => {
        socket.broadcast.emit('signal_answer', data);
    });

    socket.on('ice_candidate', (data) => {
        socket.broadcast.emit('ice_candidate', data);
    });

    socket.on('disconnect', () => {
        console.log(`Utilisateur déconnecté : ${socket.id}`);
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Serveur EVAT Quantum actif sur le port ${PORT}`);
});
