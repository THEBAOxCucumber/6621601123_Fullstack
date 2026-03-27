const express = require('express');
const app = express();

const bodyParser = require('body-parser');
const cors = require('cors');
const session = require('express-session');
const mysql = require('mysql2/promise');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = 'secret';
const REFRESH_SECRET = 'refresh_secret';
const port = 9000;

app.use(bodyParser.json());

const corsOptions = {
    origin: 'http://127.0.0.1:5500',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
};
app.use(cors(corsOptions));

app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        sameSite: 'lax'
    }
}));

let conn = null;

const initMySQL = async () => {
    try {
        conn = await mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: 'root',
            database: 'management', // 👈 แก้ตรงนี้
            port: 9906
        });
        console.log('✅ MySQL Connected');
    } catch (error) {
        console.error('❌ MySQL CONNECT ERROR:', error);
    }
};

app.post('/users', async (req, res) => {
    try {
        const { username, password, role } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'username และ password จำเป็นต้องมี'
                }
            });
        }

        const [existingUser] = await conn.query(
            'SELECT id FROM users WHERE username = ?',
            [username]
        );

        if (existingUser.length > 0) {
            return res.status(400).json({
                error: {
                    code: 'USERNAME_TAKEN',
                    message: 'ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว'
                }
            });
        }

        const password_hash = await bcrypt.hash(password, 10);

        await conn.query(
            `INSERT INTO users (id, username, password_hash, role)
             VALUES (?, ?, ?, ?)`,
            [uuidv4(), username, password_hash, role || 'DISPATCHER']
        );

        res.json({ success: true });

    } catch (error) {
        res.status(500).json({
            error: { code: 'SERVER_ERROR', message: error.message }
        });
    }
});

const authMiddleware = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            return res.status(401).json({
                error: { message: 'No token provided' }
            });
        }

        const token = authHeader.split(' ')[1];

        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded; // เก็บ user ไว้ใช้ต่อ

        next(); // ไปต่อ route
    } catch (error) {
        return res.status(401).json({
            error: { message: 'Invalid token' }
        });
    }
};

app.get('/users', authMiddleware, async (req, res) => {
    const userId = req.user.user_id;

    const [users] = await conn.query(
        'SELECT id, username, role FROM users WHERE id = ?',
        [userId]
    );

    res.json(users[0]); // ส่ง user เดียว
});

// login
app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        const [users] = await conn.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({
                error: { code: 'INVALID_CREDENTIALS', message: 'Invalid username or password' }
            });
        }

        const user = users[0];

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({
                error: { code: 'INVALID_CREDENTIALS', message: 'Invalid username or password' }
            });
        }

        const accessToken = jwt.sign(
            { user_id: user.id, role: user.role },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        const refreshToken = jwt.sign(
            { user_id: user.id },
            REFRESH_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            access_token: accessToken,
            refresh_token: refreshToken
        });

    } catch (err) {
        res.status(500).json({ error: { code: 'SERVER_ERROR', message: err.message } });
    }
});

//checkpoints
app.patch('/checkpoints/:id/status', async (req, res) => {
    const { status } = req.body;

    const [rows] = await conn.query(
        'SELECT * FROM checkpoints WHERE id = ?',
        [req.params.id]
    );

    const cp = rows[0];

    const [prev] = await conn.query(
        `SELECT * FROM checkpoints 
         WHERE trip_id=? AND sequence = ?`,
        [cp.trip_id, cp.sequence - 1]
    );

    if (prev.length > 0 && prev[0].status !== 'DEPARTED') {
        return res.status(400).json({
            error: { message: 'Previous checkpoint not completed' }
        });
    }

    await conn.query(
        'UPDATE checkpoints SET status=? WHERE id=?',
        [status, cp.id]
    );

    res.json({ success: true });
});

const alertRules = [
    {
        name: 'Vehicle Due',
        check: (v) => v.mileage_km >= v.next_service_km,
        message: 'Vehicle Due for Service'
    }
];

const runAlerts = async () => {
    const [vehicles] = await conn.query('SELECT * FROM vehicles');

    return vehicles
        .flatMap(v =>
            alertRules
                .filter(r => r.check(v))
                .map(r => ({
                    vehicle_id: v.id,
                    message: r.message
                }))
        );
};

// alerts
app.get('/alerts', async (req, res) => {
    const alerts = await runAlerts();
    res.json(alerts);
});

const logAction = async (user_id, action, resource_type, result) => {
    await conn.query(
        `INSERT INTO audit_logs (id, user_id, action, resource_type, result)
         VALUES (?, ?, ?, ?, ?)`,
        [uuidv4(), user_id, action, resource_type, result]
    );
};


initMySQL();

app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});