const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid'); 
const { pool, testDbConnection } = require('./db'); 
require('dotenv').config(); // Load environment variables from .env

const app = express();
const PORT = process.env.PORT || 3000; // API server port
const JWT_SECRET = process.env.JWT_SECRET; // JWT secret key from .env


app.use(express.json());

// Test the database connection when the server starts.
testDbConnection();


const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; 

    if (token == null) {
        // No token provided, user is unauthorized
        return res.status(401).json({ message: 'Authentication token required.' });
    }

    // Verify the token using the JWT_SECRET
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            // Token is invalid or expired
            return res.status(403).json({ message: 'Invalid or expired token.' });
        }
        // If valid, attach the user payload to the request object
        req.user = user; // user payload contains { id: userId, role: role }
        next(); // Proceed to the next middleware/route handler
    });
};


const authorizeRole = (requiredRoles) => (req, res, next) => {
    if (!req.user || !requiredRoles.includes(req.user.role)) {
        // User is not authenticated or does not have the required role
        return res.status(403).json({ message: 'Access denied: Insufficient privileges.' });
    }
    next(); 
};

// --- API Routes ---

// @route   POST /api/admin/register
// @desc    Register a new Admin
// This route is typically used for initial setup of the first admin account.
app.post('/api/admin/register', async (req, res) => {
    const { adminId, fullName, email, password } = req.body;
    // Validate incoming request data
    if (!adminId || !fullName || !email || !password) {
        return res.status(400).json({ message: 'Please enter all required fields.' });
    }
    try {
        // Check if Admin ID or Email already exists to prevent duplicates
        const [existing] = await pool.query('SELECT Admin_ID FROM Admins WHERE Admin_ID = ? OR Email = ?', [adminId, email]);
        if (existing.length > 0) {
            return res.status(409).json({ message: 'Admin ID or Email already exists.' });
        }
        // Hash the password before storing it in the database for security
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // Insert new admin into the database
        await pool.query('INSERT INTO Admins (Admin_ID, Full_Name, Email, Password_Hash) VALUES (?, ?, ?, ?)', [adminId, fullName, email, passwordHash]);
        res.status(201).json({ message: 'Admin registered successfully.' });
    } catch (err) {
        console.error('Admin registration error:', err);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// @route   POST /api/login
// @desc    Handles login requests for all user roles (Citizen, Officer, Pharmacist, Admin)
app.post('/api/login', async (req, res) => {
    const { userId, password, role } = req.body; // userId refers to e_ID, Officer_ID, etc.
    if (!userId || !password || !role) {
        return res.status(400).json({ message: 'Please provide user ID, password, and role.' });
    }

    let tableName, idColumn, passwordColumn;
    // Determine the correct table and column names based on the provided role
    switch (role.toLowerCase()) {
        case 'citizen': tableName = 'Citizens'; idColumn = 'e_ID'; passwordColumn = 'Password_Hash'; break;
        case 'officer': tableName = 'Government_Officers'; idColumn = 'Officer_ID'; passwordColumn = 'Password_Hash'; break;
        case 'pharmacist': tableName = 'Pharmacists'; idColumn = 'Pharmacist_ID'; passwordColumn = 'Password_Hash'; break;
        case 'admin': tableName = 'Admins'; idColumn = 'Admin_ID'; passwordColumn = 'Password_Hash'; break;
        default: return res.status(400).json({ message: 'Invalid role provided.' });
    }

    try {
        // Fetch the user from the database
        const [rows] = await pool.query(`SELECT ${idColumn}, ${passwordColumn} FROM ${tableName} WHERE ${idColumn} = ?`, [userId]);
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const user = rows[0];
        // Compare the provided password with the hashed password in the database
        const isMatch = await bcrypt.compare(password, user[passwordColumn]);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // Generate a JSON Web Token (JWT) upon successful authentication
        // The token includes the user's ID and role, and expires in 8 hours.
        const token = jwt.sign({ id: user[idColumn], role: role }, JWT_SECRET, { expiresIn: '8h' });
        res.status(200).json({ message: 'Login successful', token, role, userId });

    } catch (err) {
        console.error(`Login error for role ${role}:`, err);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

// --- Citizen Routes ---

// @route   GET /api/citizen/services
// @desc    Get all bookable government health services
// Accessible by citizens, officers, and admins to browse available services.
app.get('/api/citizen/services', authenticateToken, authorizeRole(['citizen', 'admin', 'officer']), async (req, res) => {
    try {
        const [services] = await pool.query('SELECT s.*, d.Department_Name FROM Services_Offered s JOIN Government_Departments d ON s.Department_ID = d.Department_ID WHERE s.Is_Bookable = TRUE');
        res.status(200).json({ services });
    } catch (err) {
        console.error('Error fetching services:', err);
        res.status(500).json({ message: 'Server error fetching services.' });
    }
});

// @route   GET /api/citizen/slots
// @desc    Get available time slots for a specific service on a given date.
// Allows filtering by officer or department (optional).
app.get('/api/citizen/slots', authenticateToken, authorizeRole(['citizen', 'admin', 'officer']), async (req, res) => {
    const { serviceId, date, officerId, departmentId } = req.query;
    if (!serviceId || !date) {
        return res.status(400).json({ message: 'Service ID and Date are required to find slots.' });
    }
    try {
        let query = `SELECT * FROM Appointment_Slots WHERE Service_ID = ? AND Slot_Date = ? AND Is_Available = TRUE AND Current_Bookings < Max_Capacity`;
        let params = [serviceId, date];
        if (officerId) {
            query += ` AND Officer_ID = ?`;
            params.push(officerId);
        }
        if (departmentId) {
            query += ` AND Department_ID = ?`;
            params.push(departmentId);
        }
        const [slots] = await pool.query(query, params);
        res.status(200).json({ slots });
    } catch (err) {
        console.error('Error fetching slots:', err);
        res.status(500).json({ message: 'Server error fetching slots.' });
    }
});

// @route   POST /api/citizen/appointments/book
// @desc    Allows a citizen to book a new appointment.
// Uses a database transaction to ensure atomicity (all or nothing) for booking and slot update.
app.post('/api/citizen/appointments/book', authenticateToken, authorizeRole(['citizen']), async (req, res) => {
    const { serviceId, slotId, appointmentDate, appointmentTime, bookedOfficerId } = req.body;
    const citizenEId = req.user.id; // Get citizen's e_ID from their authenticated token
    if (!serviceId || !slotId || !appointmentDate || !appointmentTime || !citizenEId) {
        return res.status(400).json({ message: 'Missing required appointment details.' });
    }

    const connection = await pool.getConnection(); // Get a connection from the pool
    try {
        await connection.beginTransaction(); // Start a database transaction

        // 1. Check slot availability and capacity, and lock the row for update (FOR UPDATE)
        const [slots] = await connection.query('SELECT * FROM Appointment_Slots WHERE Slot_ID = ? AND Is_Available = TRUE AND Current_Bookings < Max_Capacity FOR UPDATE', [slotId]);
        if (slots.length === 0) {
            await connection.rollback(); // Rollback transaction if slot is unavailable
            return res.status(400).json({ message: 'Appointment slot is not available or full.' });
        }
        const slot = slots[0];

        // 2. Increment Current_Bookings for the selected slot
        await connection.query('UPDATE Appointment_Slots SET Current_Bookings = Current_Bookings + 1 WHERE Slot_ID = ?', [slotId]);

        // 3. Create the new Appointment record
        const appointmentId = uuidv4(); // Generate a unique UUID for the appointment
        const referenceNumber = `REF-${Math.random().toString(36).substr(2, 9).toUpperCase()}`; // Generate a simple unique reference
        const qrCodeRef = `QR-${uuidv4()}`; // Generate a unique reference for the QR code

        await connection.query(
            'INSERT INTO Appointments (Appointment_ID, Citizen_e_ID, Service_ID, Slot_ID, Booked_Officer_ID, Appointment_Date, Appointment_Time, Status, QR_Code_Ref, Reference_Number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [appointmentId, citizenEId, serviceId, slotId, bookedOfficerId || null, appointmentDate, appointmentTime, 'Pending', qrCodeRef, referenceNumber]
        );

        await connection.commit(); // Commit the transaction if all operations succeed

        // Simulate sending a confirmation notification (in a real app, use a dedicated service)
        await connection.query(
            'INSERT INTO Notifications (Citizen_e_ID, Appointment_ID, Type, Message_Content, Send_Method) VALUES (?, ?, ?, ?, ?)',
            [citizenEId, appointmentId, 'Confirmation', `Your appointment for ${slot.Slot_Time} on ${slot.Slot_Date} is booked! Ref: ${referenceNumber}. Please upload required documents.`, 'Email']
        );

        res.status(201).json({
            message: 'Appointment booked successfully.',
            appointmentId,
            referenceNumber,
            qrCodeRef,
            slotDetails: { date: appointmentDate, time: appointmentTime }
        });

    } catch (err) {
        await connection.rollback(); // Rollback transaction if any error occurs
        console.error('Appointment booking error:', err);
        res.status(500).json({ message: 'Server error during appointment booking.' });
    } finally {
        connection.release(); // Always release the connection back to the pool
    }
});

// @route   GET /api/citizen/appointments/my
// @desc    Get all appointments for the currently logged-in citizen.
app.get('/api/citizen/appointments/my', authenticateToken, authorizeRole(['citizen']), async (req, res) => {
    const citizenEId = req.user.id;
    try {
        const [appointments] = await pool.query(
            `SELECT a.*, s.Service_Name, d.Department_Name, o.Full_Name as OfficerName, f.Feedback_ID as feedback_id
             FROM Appointments a
             JOIN Services_Offered s ON a.Service_ID = s.Service_ID
             JOIN Government_Departments d ON s.Department_ID = d.Department_ID
             LEFT JOIN Government_Officers o ON a.Booked_Officer_ID = o.Officer_ID
             LEFT JOIN Feedback f ON a.Appointment_ID = f.Appointment_ID
             WHERE a.Citizen_e_ID = ? ORDER BY a.Appointment_Date DESC, a.Appointment_Time DESC`,
            [citizenEId]
        );
        res.status(200).json({ appointments });
    } catch (err) {
        console.error('Error fetching citizen appointments:', err);
        res.status(500).json({ message: 'Server error fetching appointments.' });
    }
});

// @route   POST /api/citizen/documents/upload
// @desc    Allows a citizen to pre-submit documents for a specific appointment.
// NOTE: In a production app, `fileUrl` would be the URL returned from a cloud storage
// provider (e.g., AWS S3, Google Cloud Storage) after the actual file upload from the client.
app.post('/api/citizen/documents/upload', authenticateToken, authorizeRole(['citizen']), async (req, res) => {
    const { appointmentId, documentType, fileUrl } = req.body;
    const citizenEId = req.user.id;

    if (!appointmentId || !documentType || !fileUrl) {
        return res.status(400).json({ message: 'Appointment ID, document type, and file URL are required.' });
    }
    // Basic security: Ensure the appointment actually belongs to the logged-in citizen
    const [appointment] = await pool.query('SELECT Appointment_ID FROM Appointments WHERE Appointment_ID = ? AND Citizen_e_ID = ?', [appointmentId, citizenEId]);
    if (appointment.length === 0) {
        return res.status(403).json({ message: 'Access denied: Appointment not found or does not belong to this citizen.' });
    }

    try {
        await pool.query(
            'INSERT INTO Pre_Submitted_Documents (Appointment_ID, Citizen_e_ID, Document_Type, File_URL, Review_Status) VALUES (?, ?, ?, ?, ?)',
            [appointmentId, citizenEId, documentType, fileUrl, 'Pending']
        );
        res.status(201).json({ message: 'Document uploaded successfully. Awaiting review.' });
    } catch (err) {
        console.error('Error uploading document:', err);
        res.status(500).json({ message: 'Server error uploading document.' });
    }
});

// @route   POST /api/citizen/feedback
// @desc    Allows a citizen to submit feedback for a completed appointment.
app.post('/api/citizen/feedback', authenticateToken, authorizeRole(['citizen']), async (req, res) => {
    const { appointmentId, rating, comments } = req.body;
    const citizenEId = req.user.id;

    if (!appointmentId || !rating) {
        return res.status(400).json({ message: 'Appointment ID and rating are required.' });
    }
    if (rating < 1 || rating > 5) {
        return res.status(400).json({ message: 'Rating must be between 1 and 5.' });
    }

    try {
        // Ensure appointment belongs to citizen and its status is 'Completed'
        const [appointment] = await pool.query('SELECT Status FROM Appointments WHERE Appointment_ID = ? AND Citizen_e_ID = ?', [appointmentId, citizenEId]);
        if (appointment.length === 0) {
            return res.status(403).json({ message: 'Access denied: Appointment not found or does not belong to you.' });
        }
        if (appointment[0].Status !== 'Completed') {
            return res.status(400).json({ message: 'Feedback can only be submitted for completed appointments.' });
        }

        // Prevent duplicate feedback for the same appointment
        const [existingFeedback] = await pool.query('SELECT Feedback_ID FROM Feedback WHERE Appointment_ID = ?', [appointmentId]);
        if (existingFeedback.length > 0) {
            return res.status(409).json({ message: 'Feedback already submitted for this appointment.' });
        }

        await pool.query(
            'INSERT INTO Feedback (Citizen_e_ID, Appointment_ID, Rating, Comments) VALUES (?, ?, ?, ?)',
            [citizenEId, appointmentId, rating, comments]
        );
        res.status(201).json({ message: 'Feedback submitted successfully.' });
    } catch (err) {
        console.error('Error submitting feedback:', err);
        res.status(500).json({ message: 'Server error submitting feedback.' });
    }
});


// --- Government Officer Routes ---

// @route   GET /api/officer/appointments
// @desc    Get appointments relevant to the logged-in officer's department.
// Includes details about associated citizen and pre-submitted documents.
app.get('/api/officer/appointments', authenticateToken, authorizeRole(['officer', 'admin']), async (req, res) => {
    const officerId = req.user.id;
    const { status, date } = req.query; // Filters for status and date
    try {
        // Get the department ID of the logged-in officer
        const [officer] = await pool.query('SELECT Department_ID FROM Government_Officers WHERE Officer_ID = ?', [officerId]);
        if (officer.length === 0) {
            return res.status(404).json({ message: 'Officer not found.' });
        }
        const departmentId = officer[0].Department_ID;

        let query = `
            SELECT a.*, s.Service_Name, c.Full_Name as CitizenName, c.NIC_Number as CitizenNIC,
                   sd.Document_ID, sd.Document_Type, sd.File_URL, sd.Review_Status, sd.Reviewed_By_Officer_ID
            FROM Appointments a
            JOIN Services_Offered s ON a.Service_ID = s.Service_ID
            JOIN Citizens c ON a.Citizen_e_ID = c.e_ID
            LEFT JOIN Pre_Submitted_Documents sd ON a.Appointment_ID = sd.Appointment_ID
            WHERE s.Department_ID = ?
        `;
        let params = [departmentId];

        if (status) {
            query += ` AND a.Status = ?`;
            params.push(status);
        }
        if (date) {
            query += ` AND a.Appointment_Date = ?`;
            params.push(date);
        }
        query += ` ORDER BY a.Appointment_Date ASC, a.Appointment_Time ASC`;

        const [appointments] = await pool.query(query, params);

        // Group documents by appointment, as a single appointment can have multiple documents
        const groupedAppointments = appointments.reduce((acc, current) => {
            const existingAppt = acc.find(a => a.Appointment_ID === current.Appointment_ID);
            if (existingAppt) {
                if (current.Document_ID) { // Only add if document data exists for this row
                    existingAppt.documents.push({
                        Document_ID: current.Document_ID,
                        Document_Type: current.Document_Type,
                        File_URL: current.File_URL,
                        Review_Status: current.Review_Status,
                    });
                }
            } else {
                // Create a new appointment object, and initialize documents array if document exists
                acc.push({
                    ...current,
                    documents: current.Document_ID ? [{
                        Document_ID: current.Document_ID,
                        Document_Type: current.Document_Type,
                        File_URL: current.File_URL,
                        Review_Status: current.Review_Status,
                    }] : []
                });
            }
            // Remove redundant document fields from the main appointment object for cleaner response
            delete current.Document_ID;
            delete current.Document_Type;
            delete current.File_URL;
            delete current.Review_Status;
            delete current.Reviewed_By_Officer_ID;
            delete current.Officer_Comments;
            delete current.Review_Timestamp;

            return acc;
        }, []);


        res.status(200).json({ appointments: groupedAppointments });
    } catch (err) {
        console.error('Error fetching officer appointments:', err);
        res.status(500).json({ message: 'Server error fetching appointments.' });
    }
});

// @route   PUT /api/officer/appointments/:id/status
// @desc    Update the status of a specific appointment (e.g., Confirmed, Completed, Rescheduled).
app.put('/api/officer/appointments/:id/status', authenticateToken, authorizeRole(['officer', 'admin']), async (req, res) => {
    const { id } = req.params; // Appointment ID from URL parameters
    const { status, officerNotes, newDate, newTime } = req.body; // New status and optional details
    const officerId = req.user.id;

    if (!status) {
        return res.status(400).json({ message: 'Status is required.' });
    }

    const validStatuses = ['Confirmed', 'Rescheduled', 'Completed', 'Cancelled_By_Officer', 'No_Show'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ message: 'Invalid status provided.' });
    }

    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();

        // Verify that the officer has authority over this appointment's department
        const [appointment] = await connection.query(`
            SELECT a.Appointment_ID, a.Citizen_e_ID, a.Service_ID, so.Department_ID
            FROM Appointments a
            JOIN Services_Offered so ON a.Service_ID = so.Service_ID
            WHERE a.Appointment_ID = ?`, [id]);

        if (appointment.length === 0) {
            await connection.rollback();
            return res.status(404).json({ message: 'Appointment not found.' });
        }

        const [officerDept] = await connection.query('SELECT Department_ID FROM Government_Officers WHERE Officer_ID = ?', [officerId]);
        if (officerDept.length === 0 || officerDept[0].Department_ID !== appointment[0].Department_ID) {
            await connection.rollback();
            return res.status(403).json({ message: 'Access denied: Officer does not manage this department\'s appointments.' });
        }

        // Update the appointment status and notes
        let updateQuery = `UPDATE Appointments SET Status = ?, Officer_Notes = ?, Updated_At = CURRENT_TIMESTAMP`;
        let params = [status, officerNotes || null];

        // If rescheduling, update date and time
        if (status === 'Rescheduled' && newDate && newTime) {
            updateQuery += `, Appointment_Date = ?, Appointment_Time = ?`;
            params.push(newDate, newTime);
        }
        updateQuery += ` WHERE Appointment_ID = ?`;
        params.push(id);

        await connection.query(updateQuery, params);

        // Simulate notification to the citizen about the status update
        let notificationMsg = `Your appointment (Ref: ${appointment[0].Appointment_ID}) status updated to: ${status}.`;
        if (status === 'Rescheduled' && newDate && newTime) {
            notificationMsg += ` New time: ${newTime} on ${newDate}.`;
        }

        await connection.query(
            'INSERT INTO Notifications (Citizen_e_ID, Appointment_ID, Type, Message_Content, Send_Method) VALUES (?, ?, ?, ?, ?)',
            [appointment[0].Citizen_e_ID, id, 'Status_Update', notificationMsg, 'Email']
        );

        await connection.commit();
        res.status(200).json({ message: `Appointment ${id} status updated to ${status}.` });

    } catch (err) {
        await connection.rollback();
        console.error('Error updating appointment status:', err);
        res.status(500).json({ message: 'Server error updating appointment status.' });
    } finally {
        connection.release();
    }
});

// @route   PUT /api/officer/documents/:id/review
// @desc    Allows an officer to review and update the status of a pre-submitted document.
app.put('/api/officer/documents/:id/review', authenticateToken, authorizeRole(['officer', 'admin']), async (req, res) => {
    const { id } = req.params; // Document ID
    const { reviewStatus, officerComments } = req.body;
    const officerId = req.user.id;

    if (!reviewStatus) {
        return res.status(400).json({ message: 'Review status is required.' });
    }
    const validReviewStatuses = ['Approved', 'Rejected'];
    if (!validReviewStatuses.includes(reviewStatus)) {
        return res.status(400).json({ message: 'Invalid review status provided.' });
    }

    try {
        // Verify that the officer has authority over this document's associated department
        const [doc] = await pool.query(`
            SELECT p.*, a.Citizen_e_ID, so.Department_ID, a.Appointment_ID
            FROM Pre_Submitted_Documents p
            JOIN Appointments a ON p.Appointment_ID = a.Appointment_ID
            JOIN Services_Offered so ON a.Service_ID = so.Service_ID
            WHERE p.Document_ID = ?`, [id]);

        if (doc.length === 0) {
            return res.status(404).json({ message: 'Document not found.' });
        }

        const [officerDept] = await pool.query('SELECT Department_ID FROM Government_Officers WHERE Officer_ID = ?', [officerId]);
        if (officerDept.length === 0 || officerDept[0].Department_ID !== doc[0].Department_ID) {
            return res.status(403).json({ message: 'Access denied: Officer cannot review documents for this department.' });
        }

        await pool.query(
            'UPDATE Pre_Submitted_Documents SET Review_Status = ?, Reviewed_By_Officer_ID = ?, Officer_Comments = ?, Review_Timestamp = CURRENT_TIMESTAMP WHERE Document_ID = ?',
            [reviewStatus, officerId, officerComments || null, id]
        );

        // Simulate notification to the citizen about the document review status
        const notificationMsg = `Your submitted document (${doc[0].Document_Type}) for Appointment ${doc[0].Appointment_ID} has been ${reviewStatus}. Comments: ${officerComments || 'N/A'}.`;
        await pool.query(
            'INSERT INTO Notifications (Citizen_e_ID, Appointment_ID, Type, Message_Content, Send_Method) VALUES (?, ?, ?, ?, ?)',
            [doc[0].Citizen_e_ID, doc[0].Appointment_ID, 'Status_Update', notificationMsg, 'Email']
        );

        res.status(200).json({ message: `Document ${id} reviewed as ${reviewStatus}.` });
    } catch (err) {
        console.error('Error reviewing document:', err);
        res.status(500).json({ message: 'Server error reviewing document.' });
    }
});


// --- Admin Routes ---

// @route   GET /api/admin/users
// @desc    Retrieve a list of all users (Citizens, Officers, Admins) for management purposes.
app.get('/api/admin/users', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const [citizens] = await pool.query('SELECT e_ID as id, Full_Name as name, Email as email, "Citizen" as role FROM Citizens');
        const [officers] = await pool.query('SELECT Officer_ID as id, Full_Name as name, Email as email, "Officer" as role FROM Government_Officers');
        const [admins] = await pool.query('SELECT Admin_ID as id, Full_Name as name, Email as email, "Admin" as role FROM Admins');
        const allUsers = [...citizens, ...officers, ...admins];
        res.status(200).json({ users: allUsers });
    } catch (err) {
        console.error('Error fetching all users:', err);
        res.status(500).json({ message: 'Server error fetching users.' });
    }
});

// @route   POST /api/admin/user/create
// @desc    Allows an Admin to create new user accounts (Citizen or Officer).
app.post('/api/admin/user/create', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    const { role, id, fullName, email, password, nicNumber, dateOfBirth, gender, departmentId, slmcId } = req.body;

    if (!role || !id || !fullName || !email || !password) {
        return res.status(400).json({ message: 'Missing basic user creation fields (role, ID, full name, email, password).' });
    }
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    try {
        let query;
        let params;
        switch (role.toLowerCase()) {
            case 'citizen':
                if (!nicNumber || !dateOfBirth) return res.status(400).json({ message: 'Missing Citizen specific fields (NIC number, Date of Birth).' });
                query = 'INSERT INTO Citizens (e_ID, NIC_Number, Full_Name, Date_of_Birth, Gender, Email, Password_Hash) VALUES (?, ?, ?, ?, ?, ?, ?)';
                params = [id, nicNumber, fullName, dateOfBirth, gender || null, email, passwordHash];
                break;
            case 'officer':
                if (!departmentId) return res.status(400).json({ message: 'Missing Officer specific fields (Department ID).' });
                query = 'INSERT INTO Government_Officers (Officer_ID, Full_Name, Email, Phone_Number, Department_ID, SLMC_ID, Password_Hash) VALUES (?, ?, ?, ?, ?, ?, ?)';
                params = [id, fullName, email, null, departmentId, slmcId || null, passwordHash]; // Phone_Number can be null
                break;
            // Add 'pharmacist' case if you decide to allow admin to create pharmacists
            default:
                return res.status(400).json({ message: 'Invalid role for creation via admin.' });
        }
        await pool.query(query, params);
        res.status(201).json({ message: `${role} created successfully.` });
    } catch (err) {
        console.error('Admin user creation error:', err);
        res.status(500).json({ message: 'Server error during user creation.' });
    }
});


// @route   GET /api/admin/analytics/summary
// @desc    Provides summary data for the Admin analytics dashboard.
// Fetches total appointments, completed, no-shows, appointments by department, and average feedback.
app.get('/api/admin/analytics/summary', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const [totalAppointments] = await pool.query('SELECT COUNT(*) as count FROM Appointments');
        const [completedAppointments] = await pool.query('SELECT COUNT(*) as count FROM Appointments WHERE Status = "Completed"');
        const [noShowAppointments] = await pool.query('SELECT COUNT(*) as count FROM Appointments WHERE Status = "No_Show"');
        const [appointmentsByDept] = await pool.query(`
            SELECT d.Department_Name, COUNT(a.Appointment_ID) as count
            FROM Appointments a
            JOIN Services_Offered s ON a.Service_ID = s.Service_ID
            JOIN Government_Departments d ON s.Department_ID = d.Department_ID
            GROUP BY d.Department_Name ORDER BY count DESC
        `);
        const [averageRating] = await pool.query('SELECT AVG(Rating) as avg_rating FROM Feedback');


        res.status(200).json({
            totalAppointments: totalAppointments[0].count,
            completedAppointments: completedAppointments[0].count,
            noShowAppointments: noShowAppointments[0].count,
            appointmentsByDepartment: appointmentsByDept,
            averageFeedbackRating: averageRating[0].avg_rating || 0
        });
    } catch (err) {
        console.error('Error fetching analytics summary:', err);
        res.status(500).json({ message: 'Server error fetching analytics.' });
    }
});

// @route   GET /api/admin/departments
// @desc    Get all government departments. Useful for admin to link officers/services.
app.get('/api/admin/departments', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const [departments] = await pool.query('SELECT * FROM Government_Departments');
        res.status(200).json({ departments });
    } catch (err) {
        console.error('Error fetching departments:', err);
        res.status(500).json({ message: 'Server error fetching departments.' });
    }
});

// @route   GET /api/admin/officers
// @desc    Get all government officers. Useful for admin to manage officer details.
app.get('/api/admin/officers', authenticateToken, authorizeRole(['admin']), async (req, res) => {
    try {
        const [officers] = await pool.query('SELECT o.*, d.Department_Name FROM Government_Officers o JOIN Government_Departments d ON o.Department_ID = d.Department_ID');
        res.status(200).json({ officers });
    } catch (err) {
        console.error('Error fetching officers:', err);
        res.status(500).json({ message: 'Server error fetching officers.' });
    }
});

// --- Start the server ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});