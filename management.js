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


// POST /vehicles
app.post('/vehicles', async (req, res) => {
    try {
        const {
            license_plate,
            type,
            driver_id,
            brand,
            model,
            year,
            fuel_type,
            mileage_km,
            last_service_km,
            next_service_km
        } = req.body;

        // ✅ validation
        if (!license_plate || !type) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'license_plate และ type จำเป็นต้องมี',
                    details: {}
                }
            });
        }

        // ✅ check license ซ้ำ
        const [existing] = await conn.query(
            'SELECT id FROM vehicles WHERE license_plate = ?',
            [license_plate]
        );

        if (existing.length > 0) {
            return res.status(400).json({
                error: {
                    code: 'DUPLICATE_LICENSE',
                    message: 'license_plate นี้มีอยู่แล้ว',
                    details: {}
                }
            });
        }

        // ✅ insert

        await conn.query(
            `INSERT INTO vehicles (
                id,
                license_plate,
                type,
                status,
                driver_id,
                brand,
                model,
                year,
                fuel_type,
                mileage_km,
                last_service_km,
                next_service_km
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                id,
                license_plate,
                type,
                'IDLE', // default
                driver_id || null,
                brand || null,
                model || null,
                year || null,
                fuel_type || null,
                mileage_km || 0,
                last_service_km || null,
                next_service_km || null
            ]
        );

        res.json({
            success: true,
            data: { id }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message,
                details: {}
            }
        });
    }
});


// POST /drivers
app.post('/drivers', async (req, res) => {
    try {
        const {
            name,
            license_number,
            license_expires_at,
            phone,
            status
        } = req.body;

        // ✅ validation
        if (!name || !license_number || !license_expires_at || !phone) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'name, license_number, license_expires_at, phone จำเป็นต้องมี',
                    details: {}
                }
            });
        }

        // ✅ check license ซ้ำ
        const [existing] = await conn.query(
            'SELECT id FROM drivers WHERE license_number = ?',
            [license_number]
        );

        if (existing.length > 0) {
            return res.status(400).json({
                error: {
                    code: 'DUPLICATE_LICENSE',
                    message: 'license_number นี้ถูกใช้แล้ว',
                    details: {}
                }
            });
        }
  

        // ✅ insert
        await conn.query(
                `INSERT INTO drivers (
                id,
                name,
                license_number,
                license_expires_at,
                phone,
                status
            ) VALUES (?, ?, ?, ?, ?, ?)`,
            [
                id,
                name,
                license_number,
                license_expires_at,
                phone,
                status || 'ACTIVE'
            ]
        );

        res.json({
            success: true,
            data: { id }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message,
                details: {}
            }
        });
    }
});


// POST /trips
app.post('/trips', async (req, res) => {
    try {
        const {
            vehicle_id,
            driver_id,
            origin,
            destination,
            distance_km,
            cargo_type,
            cargo_weight_kg,
            started_at,
            ended_at
        } = req.body;

        // ✅ validation
        if (!vehicle_id || !driver_id || !origin || !destination) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'vehicle_id, driver_id, origin, destination จำเป็นต้องมี',
                    details: {}
                }
            });
        }

        // ✅ check vehicle exists
        const [vehicle] = await conn.query(
            'SELECT id FROM vehicles WHERE id = ?',
            [vehicle_id]
        );

        if (vehicle.length === 0) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_VEHICLE',
                    message: 'vehicle_id ไม่ถูกต้อง',
                    details: {}
                }
            });
        }

        // ✅ check driver exists
        const [driver] = await conn.query(
            'SELECT id FROM drivers WHERE id = ?',
            [driver_id]
        );

        if (driver.length === 0) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_DRIVER',
                    message: 'driver_id ไม่ถูกต้อง',
                    details: {}
                }
            });
        }


        // ✅ insert
        await conn.query(
            `INSERT INTO trips (
                id,
                vehicle_id,
                driver_id,
                status,
                origin,
                destination,
                distance_km,
                cargo_type,
                cargo_weight_kg,
                started_at,
                ended_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                id,
                vehicle_id,
                driver_id,
                'SCHEDULED',
                origin,
                destination,
                distance_km || null,
                cargo_type || null,
                cargo_weight_kg || null,
                started_at || null,
                ended_at || null
            ]
        );

        res.json({
            success: true,
            data: { id }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message,
                details: {}
            }
        });
    }
});

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



// POST /checkpoints
app.post('/checkpoints', async (req, res) => {
    try {
        const {
            trip_id,
            sequence,
            location_name,
            latitude,
            longitude,
            purpose,
            notes,
            arrived_at,
            departed_at
        } = req.body;

        // ✅ validation
        if (!trip_id || sequence === undefined || !location_name) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'trip_id, sequence, location_name จำเป็นต้องมี',
                    details: {}
                }
            });
        }

        // ✅ check trip exists
        const [trip] = await conn.query(
            'SELECT id FROM trips WHERE id = ?',
            [trip_id]
        );

        if (trip.length === 0) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_TRIP',
                    message: 'trip_id ไม่ถูกต้อง',
                    details: {}
                }
            });
        }

        // ✅ check sequence ซ้ำ (unique key)
        const [existing] = await conn.query(
            'SELECT id FROM checkpoints WHERE trip_id = ? AND sequence = ?',
            [trip_id, sequence]
        );

        if (existing.length > 0) {
            return res.status(400).json({
                error: {
                    code: 'DUPLICATE_SEQUENCE',
                    message: 'sequence นี้มีใน trip แล้ว',
                    details: {}
                }
            });
        }

        const id = uuidv4();

        // ✅ insert
        await conn.query(
            `INSERT INTO checkpoints (
                id,
                trip_id,
                sequence,
                status,
                location_name,
                latitude,
                longitude,
                purpose,
                notes,
                arrived_at,
                departed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                id,
                trip_id,
                sequence,
                'PENDING',
                location_name,
                latitude || null,
                longitude || null,
                purpose || null,
                notes || null,
                arrived_at || null,
                departed_at || null
            ]
        );

        res.json({
            success: true,
            data: { id }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message,
                details: {}
            }
        });
    }
});
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



// POST /maintenance
app.post('/maintenance', async (req, res) => {
    try {
        const {
            vehicle_id,
            type,
            scheduled_at,
            mileage_at_service,
            technician,
            cost_thb,
            notes
        } = req.body;

        // ✅ validation
        if (!vehicle_id || !type || !scheduled_at) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'vehicle_id, type, scheduled_at จำเป็นต้องมี',
                    details: {}
                }
            });
        }

        // ✅ check vehicle exists
        const [vehicle] = await conn.query(
            'SELECT id FROM vehicles WHERE id = ?',
            [vehicle_id]
        );

        if (vehicle.length === 0) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_VEHICLE',
                    message: 'vehicle_id ไม่ถูกต้อง',
                    details: {}
                }
            });
        }

        const id = uuidv4();

        // ✅ insert
        await conn.query(
            `INSERT INTO maintenance (
                id,
                vehicle_id,
                status,
                type,
                scheduled_at,
                mileage_at_service,
                technician,
                cost_thb,
                notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                id,
                vehicle_id,
                'SCHEDULED',
                type,
                scheduled_at,
                mileage_at_service || null,
                technician || null,
                cost_thb || null,
                notes || null
            ]
        );

        res.json({
            success: true,
            data: { id }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message,
                details: {}
            }
        });
    }
});



// POST /maintenance-parts
app.post('/maintenance-parts', async (req, res) => {
    try {
        const {
            maintenance_id,
            part_name,
            part_number,
            quantity,
            cost_thb
        } = req.body;

        // ✅ validation
        if (!maintenance_id || !part_name) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'maintenance_id และ part_name จำเป็นต้องมี',
                    details: {}
                }
            });
        }

        // ✅ check maintenance exists
        const [maintenance] = await conn.query(
            'SELECT id FROM maintenance WHERE id = ?',
            [maintenance_id]
        );

        if (maintenance.length === 0) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_MAINTENANCE',
                    message: 'maintenance_id ไม่ถูกต้อง',
                    details: {}
                }
            });
        }

        const id = uuidv4();

        // ✅ insert
        await conn.query(
            `INSERT INTO maintenance_parts (
                id,
                maintenance_id,
                part_name,
                part_number,
                quantity,
                cost_thb
            ) VALUES (?, ?, ?, ?, ?, ?)`,
            [
                id,
                maintenance_id,
                part_name,
                part_number || null,
                quantity || 1,
                cost_thb || null
            ]
        );

        res.json({
            success: true,
            data: { id }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message,
                details: {}
            }
        });
    }
});


// POST /audit-logs
app.post('/audit-logs', authMiddleware, async (req, res) => {
    try {
        const {
            action,
            resource_type,
            resource_id,
            result,
            detail
        } = req.body;

        const user_id = req.user.user_id;

        // ✅ validation
        if (!action || !resource_type || !result) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'action, resource_type, result จำเป็นต้องมี',
                    details: {}
                }
            });
        }

        const id = uuidv4();

        const ip =
            req.headers['x-forwarded-for'] ||
            req.socket.remoteAddress ||
            null;

        // ✅ insert
        await conn.query(
            `INSERT INTO audit_logs (
                id,
                user_id,
                action,
                resource_type,
                resource_id,
                ip_address,
                result,
                detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                id,
                user_id,
                action,
                resource_type,
                resource_id || null,
                ip,
                result,
                detail ? JSON.stringify(detail) : null
            ]
        );

        res.json({
            success: true,
            data: { id }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message,
                details: {}
            }
        });
    }
});


initMySQL();

app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});