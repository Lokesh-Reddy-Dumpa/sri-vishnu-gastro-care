const WebSocket = require('ws');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const { encryptText } = require('./security');

const app = express();

// Security Hardening
app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_ORIGIN || '*' }));
app.use(express.json({ limit: '10kb' }));

// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests. Please try again later.' }
});
app.use('/api/', apiLimiter);

// Supabase Connection
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
        auth: { persistSession: false },
        realtime: {
            transport: WebSocket
        }
    }
);

// Audit Logging Function
const logAudit = async (userId, action, resource, ip) => {
    await supabase.from('audit_trail').insert([
        { user_id: userId, action, resource, ip_address: ip }
    ]);
};

// Health Check Route
app.get('/health', (req, res) => res.json({ status: 'Healthcare API active and compliant' }));

// Appointment Route (DPDP Compliant)
app.post('/api/appointments', async (req, res) => {
    try {
        const { patient_id, doctor_name, specialty, appointment_date, notes, consent_given } = req.body;

        if (!consent_given) {
            return res.status(400).json({
                error: 'DPDP Compliance Error: Explicit user consent is mandatory.'
            });
        }

        // 1. Record Consent Log
        await supabase.from('consent_logs').insert([{
            user_id: patient_id || null,
            purpose: 'Appointment Booking & Consultation',
            ip_address: req.ip,
            is_granted: true
        }]);

        // 2. Encrypt sensitive notes
        const encryptedNotes = encryptText(notes);

        // 3. Save Appointment
        const { data, error } = await supabase.from('appointments').insert([{
            patient_id: patient_id || null,
            doctor_name,
            specialty,
            appointment_date,
            notes_encrypted: encryptedNotes
        }]).select();

        if (error) throw error;

        // 4. Record Audit Log
        await logAudit(patient_id || null, 'CREATE_APPOINTMENT', 'appointments', req.ip);

        res.status(201).json({ success: true, data });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Compliant Backend running locally on port ${PORT}`));