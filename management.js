const express = require('express');
const app = express();

const cors = require('cors');
const session = require('express-session');
const mysql = require('mysql2/promise');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = 'secret';
const REFRESH_SECRET = 'refresh_secret';
const port = 9000;

app.use(express.json());

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

// POST /users
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
        console.log("HEADER:", authHeader);
        if (!authHeader) {
            return res.status(401).json({
                error: { message: 'No token provided' }
            });
        }

        const token = authHeader.split(' ')[1];
        console.log("TOKEN:", token);
        const decoded = jwt.verify(token, JWT_SECRET);
        console.log("DECODED:", decoded);
        req.user = decoded; // เก็บ user ไว้ใช้ต่อ

        next(); // ไปต่อ route
    } catch (error) {
        console.log("JWT ERROR:", error.message);
        return res.status(401).json({
            error: { message: 'Invalid token' }
        });
    }
};


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

        const id = await generateVehiclesId();

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
                "TRUCK", "VAN", "MOTORCYCLE", "PICKUP",
                "ACTIVE", "IDLE", "MAINTENANCE", "RETIRED",
                driver_id || null,
                brand || null,
                model || null,
                year || null,
                "DIESEL", "GASOLINE", "ELECTRIC", "HYBRID",
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

        if (!name || !license_number || !license_expires_at || !phone) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'name, license_number, license_expires_at, phone จำเป็นต้องมี'
                }
            });
        }

        const [existing] = await conn.query(
            'SELECT id FROM drivers WHERE license_number = ?',
            [license_number]
        );

        if (existing.length > 0) {
            return res.status(400).json({
                error: {
                    code: 'DUPLICATE_LICENSE',
                    message: 'license_number นี้ถูกใช้แล้ว'
                }
            });
        }

        // 🔥 ใช้ custom id
        const id = await generateDriverId();

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
                "ACTIVE", "INACTIVE", "SUSPENDED"
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
                message: err.message
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

        const id = await generateTripId();

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
                "SCHEDULED", "IN_PROGRESS", "COMPLETED", "CANCELLED",
                origin,
                destination,
                distance_km || null,
                "GENERAL", "FRAGILE", "HAZARDOUS", "REFRIGERATED",
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
            location_name,
            latitude,
            longitude,
            purpose,
            notes,
            arrived_at,
            departed_at
        } = req.body;

        // ✅ validation
        if (!trip_id || !location_name) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'trip_id, location_name จำเป็นต้องมี'
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
                    message: 'trip_id ไม่ถูกต้อง'
                }
            });
        }

        // 🔥 auto generate sequence
        const [rows] = await conn.query(
            'SELECT MAX(sequence) as maxSeq FROM checkpoints WHERE trip_id = ?',
            [trip_id]
        );

        const sequence = (rows[0].maxSeq || 0) + 1;

        // ✅ generate id
        const id = await generateCheckpointId();

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
            data: { id, sequence }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: err.message
            }
        });
    }
});

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

        const id = await generateMaintenanceId();

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

        const user_id = req.user.id;

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

async function generateDriverId() {
    const [rows] = await conn.query(`
        SELECT id FROM drivers
        ORDER BY id DESC
        LIMIT 1
    `);

    if (rows.length === 0) {
        return 'drv_001';
    }

    const lastId = rows[0].id; // เช่น drv_007
    const number = parseInt(lastId.split('_')[1]);
    const newNumber = number + 1;

    return 'drv_' + String(newNumber).padStart(3, '0');
}

async function generateVehiclesId() {
    const [rows] = await conn.query(`
        SELECT id FROM vehicles
        ORDER BY id DESC
        LIMIT 1
    `);

    if (rows.length === 0) {
        return 'veh_001';
    }

    const lastId = rows[0].id; // เช่น veh_007
    const number = parseInt(lastId.split('_')[1]);
    const newNumber = number + 1;

    return 'veh_' + String(newNumber).padStart(3, '0');
}

async function generateTripId() {
    const [rows] = await conn.query(`
        SELECT id FROM trips
        ORDER BY id DESC
        LIMIT 1
    `);

    if (rows.length === 0) {
        return 'trp_001';
    }

    const lastId = rows[0].id;
    const number = parseInt(lastId.split('_')[1]);
    const newNumber = number + 1;

    return 'trp_' + String(newNumber).padStart(3, '0');
}

async function generateCheckpointId() {
    const [rows] = await conn.query(`
        SELECT id FROM checkpoints
        ORDER BY id DESC
        LIMIT 1
    `);

    if (rows.length === 0) {
        return 'chk_001';
    }

    const lastId = rows[0].id;
    const number = parseInt(lastId.split('_')[1]);
    const newNumber = number + 1;

    return 'chk_' + String(newNumber).padStart(3, '0');
}

async function generateMaintenanceId() {
    const [rows] = await conn.query(`
        SELECT id FROM maintenance
        ORDER BY id DESC
        LIMIT 1
    `);

    if (rows.length === 0) {
        return 'mnt_001';
    }

    const lastId = rows[0].id;
    const number = parseInt(lastId.split('_')[1]);
    const newNumber = number + 1;

    return 'mnt_' + String(newNumber).padStart(3, '0');
}

app.post('/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 1. check input
        if (!username || !password) {
            return res.status(400).json({
                error: {
                    code: 'INVALID_INPUT',
                    message: 'username และ password จำเป็นต้องมี'
                }
            });
        }

        // 2. หา user
        const [users] = await conn.query(
            'SELECT * FROM users WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            return res.status(401).json({
                error: {
                    code: 'INVALID_CREDENTIALS',
                    message: 'username หรือ password ไม่ถูกต้อง'
                }
            });
        }

        const user = users[0];

        // 3. compare password
        const isMatch = await bcrypt.compare(password, user.password_hash);

        if (!isMatch) {
            return res.status(401).json({
                error: {
                    code: 'INVALID_CREDENTIALS',
                    message: 'username หรือ password ไม่ถูกต้อง'
                }
            });
        }

        // 4. create token
        const accessToken = jwt.sign(
            {
                id: user.id,
                username: user.username,
                role: user.role
            },
            JWT_SECRET,
            { expiresIn: '15m' }
        );

        res.json({
            success: true,
            accessToken
        });

    } catch (error) {
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: error.message
            }
        });
    }
});

// GET /users
app.get('/users', authMiddleware, async (req, res) => {
    try {
        const { role, username } = req.query;

        // ✅ เช็คสิทธิ์ (เฉพาะ ADMIN เท่านั้น)
        if (req.user.role !== 'ADMIN') {
            return res.status(403).json({
                error: {
                    code: 'FORBIDDEN',
                    message: 'ไม่มีสิทธิ์เข้าถึงข้อมูลผู้ใช้'
                }
            });
        }

        // ✅ build query ตามเงื่อนไข
        let sql = 'SELECT id, username, role FROM users WHERE 1=1';
        let params = [];

        if (role) {
            sql += ' AND role = ?';
            params.push(role);
        }

        if (username) {
            sql += ' AND username LIKE ?';
            params.push(`%${username}%`);
        }

        const [users] = await conn.query(sql, params);

        res.json({
            success: true,
            data: users
        });

    } catch (error) {
        res.status(500).json({
            error: {
                code: 'SERVER_ERROR',
                message: error.message
            }
        });
    }
});

// GET (ทุกคนดูได้)
app.get('/vehicles', async (req, res) => {
  const [rows] = await conn.query(`
    SELECT 
      id,
      license_plate,
      type,
      brand,
      model,
      status,
      mileage_km,
      next_service_km,
      driver_name
    FROM vehicles
  `);

  res.json({
    success: true,
    data: rows
  });
});

// POST (admin เท่านั้น)
app.post('/vehicles', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ message: 'Forbidden' });
  }

  const { id, license_plate, status } = req.body;

  await conn.query(
    'INSERT INTO vehicles (id, license_plate, status) VALUES (?, ?, ?)',
    [id, license_plate, status]
  );

  res.json({ success: true });
});

app.put('/vehicles/:id', async (req, res) => {
  const { status } = req.body;

  await conn.query(
    'UPDATE vehicles SET status = ? WHERE id = ?',
    [status, req.params.id]
  );

  res.json({ success: true });
});

// DELETE
app.delete('/vehicles/:id', authMiddleware, async (req, res) => {
  if (req.user.role !== 'ADMIN') {
    return res.status(403).json({ message: 'Forbidden' });
  }

  await conn.query('DELETE FROM vehicles WHERE id = ?', [req.params.id]);

  res.json({ success: true });
});

initMySQL();

app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});