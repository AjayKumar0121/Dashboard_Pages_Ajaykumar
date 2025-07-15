const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(cors());

// Configure CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Accept');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400');
    console.log(`Setting CORS headers for ${req.method} ${req.path}`);
    console.log('Response headers:', res.getHeaders());
    next();
});

// Log OPTIONS requests
app.options('*', (req, res) => {
    console.log('Received OPTIONS request at', new Date().toISOString());
    console.log('Request headers:', req.headers);
    res.status(204).send();
});

app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'Uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(UploadsDir, { recursive: true });
}

// PostgreSQL connection
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'new_employee_db',
    password: 'Password@12345', 
    port: 5432
});

// Multer configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadsDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        cb(null, file.fieldname + '-' + uniqueSuffix + ext);
    }
});

const upload = multer({
    storage,
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Only PDF, JPG, and PNG files are allowed'));
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

// Initialize database
async function initializeDatabase() {
    try {
        console.log('Initializing database...');
       
        await pool.query(`
            CREATE TABLE if not exists claims (
                claim_id VARCHAR(20) PRIMARY KEY,
                employee_name VARCHAR(100),
                employee_email VARCHAR(100),
                employee_id VARCHAR(10),
                department VARCHAR(50),
                claim_date DATE,
                amount DECIMAL(10,2),
                description TEXT,
                type VARCHAR(50),
                status VARCHAR(20),
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        `);
        await pool.query(`
            CREATE TABLE if not exists documents (
                id SERIAL PRIMARY KEY,
                claim_id VARCHAR(20) REFERENCES claims(claim_id) ON DELETE CASCADE,
                file_name VARCHAR(255),
                file_path VARCHAR(255),
                uploaded_at TIMESTAMP
            )
        `);
        console.log('Database initialized: tables created');
    } catch (error) {
        console.error('Error initializing database:', error.message, error.stack);
        process.exit(1);
    }
}

// POST /api/claims
app.post('/api/claims', upload.array('documents', 5), async (req, res) => {
    console.log('Received POST /api/claims at', new Date().toISOString());
    console.log('Request headers:', req.headers);
    console.log('Request body:', req.body);
    console.log('Files received:', req.files ? req.files.map(f => ({
        originalname: f.originalname,
        mimetype: f.mimetype,
        size: f.size,
        path: f.path
    })) : 'None');

    try {
        const { empName, empEmail, empId, department, claimDate, amount, description, type } = req.body;
        console.log('Parsed fields:', { empName, empEmail, empId, department, claimDate, amount, description, type });

        if (!empName || !empEmail || !empId || !department || !claimDate || !amount || !description || !type) {
            console.log('Validation failed: Missing required fields');
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!/^ATS0[1-9]\d{2}$/.test(empId)) {
            console.log('Validation failed: Invalid empId format');
            return res.status(400).json({ error: 'Employee ID must be ATS0 followed by 3 digits (e.g., ATS0123)' });
        }

        if (!/^[a-zA-Z0-9._%+-]+@(gmail|outlook)\.com$/.test(empEmail)) {
            console.log('Validation failed: Invalid email');
            return res.status(400).json({ error: 'Email must be a valid @gmail.com or @outlook.com address' });
        }

        const amountValue = parseFloat(amount);
        if (isNaN(amountValue) || amountValue <= 0 || amountValue > 50000) {
            console.log('Validation failed: Invalid amount');
            return res.status(400).json({ error: 'Amount must be between ₹0.01 and ₹50,000' });
        }

        const claimDateObj = new Date(claimDate);
        const today = new Date();
        const threeMonthsAgo = new Date();
        threeMonthsAgo.setMonth(today.getMonth() - 3);
        if (claimDateObj > today || claimDateObj < threeMonthsAgo) {
            console.log('Validation failed: Invalid claim date');
            return res.status(400).json({ error: 'Claim date must be within the last 3 months and not in the future' });
        }

        if (!req.files || req.files.length === 0) {
            console.log('Validation failed: No documents uploaded');
            return res.status(400).json({ error: 'At least one document is required' });
        }

        const claimId = `CLM-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
        console.log('Generated claimId:', claimId);

        const query = `
            INSERT INTO claims (claim_id, employee_name, employee_email, employee_id, department, claim_date, amount, description, type, status, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING claim_id
        `;
        const values = [
            claimId,
            empName,
            empEmail,
            empId,
            department,
            claimDate,
            amountValue,
            description,
            type,
            'pending',
            new Date(),
            new Date()
        ];
        console.log('Executing SQL INSERT with values:', values);

        const result = await pool.query(query, values);
        console.log('Database insert result:', result.rows);

        // Process each uploaded file
        for (const file of req.files) {
            // Ensure the file exists before saving to database
            if (!fs.existsSync(file.path)) {
                console.error('File not saved to disk:', file.path);
                continue;
            }

            const docQuery = `
                INSERT INTO documents (claim_id, file_name, file_path, uploaded_at)
                VALUES ($1, $2, $3, $4)
                RETURNING id
            `;
            const docValues = [
                claimId,
                file.originalname,
                file.path,  // This stores the full path to the file
                new Date()
            ];
            console.log('Inserting document:', docValues);
            const docResult = await pool.query(docQuery, docValues);
            console.log('Document insert result:', docResult.rows);
        }

        console.log('Claim and documents saved successfully');
        res.status(201).json({ 
            message: 'Claim submitted successfully', 
            claimId,
            documents: req.files.map(f => ({
                originalName: f.originalname,
                storedPath: f.path
            }))
        });
    } catch (error) {
        console.error('Error processing POST /api/claims:', error.message, error.stack);
        
        // Clean up uploaded files if there was an error
        if (req.files && req.files.length > 0) {
            req.files.forEach(file => {
                try {
                    if (fs.existsSync(file.path)) {
                        fs.unlinkSync(file.path);
                        console.log('Deleted file due to error:', file.path);
                    }
                } catch (err) {
                    console.error('Error deleting file:', err.message);
                }
            });
        }
        
        res.status(500).json({ error: 'Server error while submitting claim' });
    }
});

// GET /api/claims
app.get('/api/claims', async (req, res) => {
    console.log('Received GET /api/claims at', new Date().toISOString());
    console.log('Request headers:', req.headers);
    console.log('Query params:', req.query);

    try {
        const { employee_id, claim_id, status } = req.query;
        let query = 'SELECT * FROM claims WHERE 1=1';
        const values = [];

        if (employee_id) {
            if (!/^ATS0[1-9]\d{2}$/.test(employee_id)) {
                console.log('Validation failed: Invalid employee_id format');
                return res.status(400).json({ error: 'Employee ID must be ATS0 followed by 3 digits' });
            }
            values.push(employee_id);
            query += ` AND employee_id = $${values.length}`;
        }
        if (claim_id) {
            values.push(claim_id);
            query += ` AND claim_id = $${values.length}`;
        }
        if (status) {
            values.push(status);
            query += ` AND status = $${values.length}`;
        }

        query += ' ORDER BY created_at DESC';
        console.log('Executing SQL SELECT:', query, 'with values:', values);
        const result = await pool.query(query, values);
        
        // For each claim, get its documents
        const claimsWithDocuments = await Promise.all(result.rows.map(async claim => {
            const docsQuery = 'SELECT id, file_name, file_path FROM documents WHERE claim_id = $1';
            const docsResult = await pool.query(docsQuery, [claim.claim_id]);
            return {
                ...claim,
                documents: docsResult.rows
            };
        }));
        
        console.log('Returning claims with documents');
        res.json(claimsWithDocuments);
    } catch (error) {
        console.error('Error processing GET /api/claims:', error.message, error.stack);
        res.status(500).json({ error: 'Server error while fetching claims' });
    }
});

// GET /api/claims/:claimId/documents
app.get('/api/claims/:claimId/documents', async (req, res) => {
    console.log('Received GET /api/claims/:claimId/documents at', new Date().toISOString());
    console.log('Request headers:', req.headers);
    console.log('Params:', req.params);

    try {
        const { claimId } = req.params;
        const query = 'SELECT id, claim_id, file_name, file_path, uploaded_at FROM documents WHERE claim_id = $1';
        console.log('Executing SQL SELECT for documents with claim_id:', claimId);
        const result = await pool.query(query, [claimId]);
        
        // Verify files exist before returning them
        const documentsWithExistence = await Promise.all(result.rows.map(async doc => {
            const exists = fs.existsSync(doc.file_path);
            return {
                ...doc,
                file_exists: exists,
                url: exists ? `/uploads/${path.basename(doc.file_path)}` : null
            };
        }));
        
        console.log('Database select result with existence check:', documentsWithExistence);
        res.json(documentsWithExistence);
    } catch (error) {
        console.error('Error processing GET /api/claims/:claimId/documents:', error.message, error.stack);
        res.status(500).json({ error: 'Server error while fetching documents' });
    }
});

// GET /api/documents/:documentId
app.get('/api/documents/:documentId', async (req, res) => {
    console.log('Received GET /api/documents/:documentId at', new Date().toISOString());
    console.log('Params:', req.params);

    try {
        const { documentId } = req.params;
        const query = 'SELECT file_path FROM documents WHERE id = $1';
        const result = await pool.query(query, [documentId]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }
        
        const filePath = result.rows[0].file_path;
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found on server' });
        }
        
        res.sendFile(filePath);
    } catch (error) {
        console.error('Error processing GET /api/documents/:documentId:', error.message, error.stack);
        res.status(500).json({ error: 'Server error while fetching document' });
    }
});

// PATCH /api/claims/:claimId
app.patch('/api/claims/:claimId', async (req, res) => {
    console.log('Received PATCH /api/claims/:claimId at', new Date().toISOString());
    console.log('Request headers:', req.headers);
    console.log('Params:', req.params);
    console.log('Request body:', req.body);

    try {
        const { claimId } = req.params;
        const { status } = req.body;

        if (!['approved', 'rejected'].includes(status)) {
            console.log('Validation failed: Invalid status');
            return res.status(400).json({ error: 'Status must be approved or rejected' });
        }

        const query = 'UPDATE claims SET status = $1, updated_at = $2 WHERE claim_id = $3 RETURNING *';
        const values = [status, new Date(), claimId];
        console.log('Executing SQL UPDATE with values:', values);
        const result = await pool.query(query, values);

        if (result.rows.length === 0) {
            console.log('No claim found for claim_id:', claimId);
            return res.status(404).json({ error: 'Claim not found' });
        }

        console.log('Claim status updated:', result.rows[0]);
        res.json(result.rows[0]);
    } catch (error) {
        console.error('Error processing PATCH /api/claims/:claimId:', error.message, error.stack);
        res.status(500).json({ error: 'Server error while updating claim' });
    }
});

// Serve static files
app.use(express.static(path.join(__dirname, 'Frontend')));

// Error handling
app.use((err, req, res, next) => {
    console.error('Server error:', err.message, err.stack);
    if (err.message.includes('Only PDF, JPG, and PNG files are allowed')) {
        return res.status(400).json({ error: err.message });
    }
    if (err.code === 'LIMIT_FILE_SIZE') {
        return res.status(400).json({ error: 'File size exceeds 5MB limit' });
    }
    if (err instanceof multer.MulterError) {
        return res.status(400).json({ error: err.message });
    }
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
const PORT = 3407;
const HOST = '0.0.0.0'; // Listen on all interfaces

app.listen(PORT, HOST, async () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
    try {
        await initializeDatabase();
        console.log('Database initialization complete');
    } catch (error) {
        console.error('Failed to initialize database:', error);
        process.exit(1);
    }
});
