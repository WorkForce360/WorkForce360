const express = require('express');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
const mysql = require('mysql2/promise');
const session = require('express-session');
const MySQLStore = require("express-mysql-session")(session);
const nodemailer = require("nodemailer");


const app = express();
const port = 3001;
const saltRounds = 10;

// ✅ MySQL Connection Pool
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '2525',
    database: 'workforce360',
    port: 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ✅ Session Store Options - FIXED
const sessionStoreOptions = {
    expiration: 86400000,
    createDatabaseTable: true,
    schema: {
        tableName: "sessions",
        columnNames: {
            session_id: "session_id",
            expires: "expires",
            data: "data"
        }
    }
};
const sessionStore = new MySQLStore(sessionStoreOptions, pool);

// ✅ Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    key: "session_cookie_name",
    secret: "your_secret_key",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 86400000
    }
}));

// ✅ Check Database Connection
pool.getConnection()
    .then(conn => {
        console.log('✅ Connected to MySQL Database');
        conn.release();
    })
    .catch(err => {
        console.error('❌ Database connection failed:', err);
    });

//EMAIL API
// Nodemailer Transporter Setup (Example using Gmail)
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "workforce360org@gmail.com",  // Replace with your email
        pass: "qlxh btdr atyr dfye"     // Replace with App Password (NOT your regular password)
    }
});

//Send an email
function sendWelcomeEmail(toEmail, fullName,hrId) {
    const mailOptions = {
        from: '"WorkForce360" workforce360org@gmail.com',  // Sender address
        to: toEmail,                                   // Recipient (new HR)
        subject: "Welcome to WorkForce360!",
        html: `
            <h1>Hello ${fullName},</h1>
            <p>Welcome to <b>WorkForce360</b>! Your account has been successfully created.</p>
            <p>We are excited to have you on board with your HR ID being: ${hrId}. Please login and start managing your workforce efficiently.</p>
            <p>Regards,<br>WorkForce360 Team</p>
        `
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.error('❌ Error sending email:', error);
        }
        console.log('✅ Welcome Email sent: ' + info.response);
    });
}

//Send an to emp email (email, 
function sendEmpWelcomeEmail(toEmail,name,hashedPassword,employeeID) {
    const mailOptions = {
        from: '"WorkForce360" workforce360org@gmail.com',  // Sender address
        to: toEmail,                                   // Recipient (new HR)
        subject: "Welcome to WorkForce360!",
        html: `
            <h1>Hello ${name},</h1>
            <p>Welcome to <b>WorkForce360</b>! Your account has been successfully created.</p>
            <p>We are excited to have you on board with your Employee ID being: ${employeeID} with password ${hashedPassword}. Please login and start managing your workforce efficiently.</p>
            <p>Regards,<br>WorkForce360 Team</p>
        `
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.error('❌ Error sending email:', error);
        }
        console.log('✅ Welcome Email sent: ' + info.response);
    });
}


// ✅ HR Signup Route : WORKING
app.post('/signupHR', async (req, res) => {
    const { fullName, hrId, email, password } = req.body;
    if (!fullName || !hrId || !email || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        const connection = await pool.getConnection();
        await connection.query(
            'INSERT INTO HR (HR_ID, password, name, email) VALUES (?, ?, ?, ?)', 
            [hrId, hashedPassword, fullName, email]
        );
        connection.release();
        
        // Send Welcome Email
        sendWelcomeEmail(email, fullName,hrId);

        res.status(200).json({ success: true, message: 'HR Signup Successful' });
    } catch (error) {
        console.error('❌ Database Error:', error);
        res.status(500).json({ success: false, message: 'Database error' });
    }
});

// ✅ HR Login Route (Stores HR Session)
app.post("/loginHR", async (req, res) => {
    const { hrId, email, password } = req.body;
    if (!hrId || !email || !password) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    try {
        const connection = await pool.getConnection();
        const [rows] = await connection.query("SELECT * FROM HR WHERE HR_ID = ? AND email = ?", [hrId, email]);
        connection.release();

        if (rows.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const hr = rows[0];
        const passwordMatch = await bcrypt.compare(password, hr.password);
        if (!passwordMatch) {
            return res.status(401).json({ success: false, message: "Invalid password" });
        }

        req.session.loggedInHR = { name: hr.name, hrId: hr.HR_ID };

        res.status(200).json({ success: true, message: "Login successful", hr: req.session.loggedInHR });

    } catch (error) {
        console.error("❌ Database Error:", error);
        res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// ✅ Employee Login : WORKING
app.post('/loginEmp', async (req, res) => {
    const { employeeId, email, password } = req.body;

    if (!employeeId || !email || !password) {
        return res.status(400).json({ success: false, message: 'Please provide all fields' });
    }

    try {
        
        const connection = await pool.getConnection();
        console.log("Login Request Data:",{employeeId,email,password});
        // ✅ Query the employees table
        const query = `SELECT * FROM employees WHERE employeeID = ? AND email = ?`;
        const [results] = await connection.query(query, [employeeId, email]);

        
        console.log("Database Query Results:", results);
        connection.release();
        if (results.length === 0) {
            return res.status(404).json({ success: false, message: "Invalid credentials" });
        }

        const employee = results[0];
        if (password !== employee.password) {
            return res.status(401).json({ success: false, message: "Invalid Password" });
        }
        // ✅ Store Employee Session
        req.session.loggedInEmp = {
            name: employee.name,
            employeeId: employee.employeeID,
            email: employee.email,
            department: employee.department,
            role: employee.role,
            hrId: employee.hrId
        };

        res.status(200).json({ success: true, message: 'Login successful', employee: req.session.loggedInEmp });

    } catch (error) {
        console.error('❌ Database Error:', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

// ✅ Get HR Session Data
app.get("/getLoggedInHR", (req, res) => {
    console.log("Session Data:", req.session);  // Debugging log
    if (!req.session.loggedInHR) {
        return res.status(401).json({ success: false, message: "Not logged in" });
    }
    res.json({ success: true, hr: req.session.loggedInHR });
});

// ✅ Get Employee Session Data
app.get("/getLoggedInEmp", (req, res) => {
    if (!req.session.loggedInEmp) {
        return res.status(401).json({ success: false, message: "Not logged in" });
    }
    res.json({ success: true, employee: req.session.loggedInEmp });
});

app.get("/getLoggedInEmp1", async (req, res) => {
    if (!req.session.loggedInEmp) {
        return res.status(401).json({ success: false, message: "Not logged in" });
    }

    const employeeId = req.session.loggedInEmp.employeeId;

    try {
        const sql = `
            SELECT e.employeeID, e.name, e.email, e.role, e.department, e.address, e.hrId, h.HR_ID, h.name AS hrName
            FROM employees e
            LEFT JOIN hr h ON e.hrId = h.HR_ID
            WHERE e.employeeID = ?
        `;

        const [results] = await pool.query(sql, [employeeId]);

        if (results.length === 0) {
            return res.status(404).json({ success: false, message: "Employee not found" });
        }

        res.json({ success: true, employee: results[0] });
    } catch (error) {
        console.error("Error fetching employee data:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});



// ✅ Add Employee : WORKING
app.post("/addEmployee", async (req, res) => {
    const { hrId, name, address, employeeID, password, email, phone, department, role } = req.body;

    if (!hrId || !name || !address || !employeeID || !password || !email || !phone || !department || !role) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    try {
        const hashedPassword = password; // ✅ Hash Password for Security
        const connection = await pool.getConnection();

        // ✅ Ensure `employees` table exists
        await connection.query(`
            CREATE TABLE IF NOT EXISTS employees (
                id INT AUTO_INCREMENT PRIMARY KEY,
                hrId INT NOT NULL,
                name VARCHAR(255),
                address TEXT,
                employeeID VARCHAR(50) UNIQUE,
                password VARCHAR(255),
                email VARCHAR(100) UNIQUE,
                phone VARCHAR(20),
                department VARCHAR(100),
                role VARCHAR(100),
                createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // ✅ Insert Employee
        await connection.query(
            `INSERT INTO employees (hrId, name, address, employeeID, password, email, phone, department, role)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`,
            [hrId, name, address, employeeID, hashedPassword, email, phone, department, role]
        );
        // Send Welcome Email
        sendEmpWelcomeEmail(email, name,hashedPassword,employeeID);
        connection.release();
        res.status(200).json({ success: true, message: "Employee added successfully" });

    } catch (error) {
        res.status(500).json({ success: false, message: "Database error", error });
        console.error("❌ Error adding employee:", error);
    }
});

// ✅ Delete Employee : WORKING
app.delete('/deleteEmployee/:employeeID', async (req, res) => {
    const { employeeID } = req.params;

    try {
        const connection = await pool.getConnection();

        // ✅ Delete Employee from `employees` table
        const [result] = await connection.query(`DELETE FROM employees WHERE employeeID = ?`, [employeeID]);

        connection.release();

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Employee not found" });
        }

        res.json({ success: true, message: "Employee deleted successfully" });

    } catch (error) {
        console.error("❌ Error Deleting Employee:", error);
        res.status(500).json({ error: "Database error", details: error });
    }
});

// Update Employee Route
app.put('/updateEmployee/:employeeId', async (req, res) => {
    const employeeId = req.params.employeeId;
    const { phone, address, department, role } = req.body;

    // Check if all fields are provided
    if (!phone || !address || !department || !role) {
        return res.status(400).json({ message: 'All fields (phone, address, department, role) are required.' });
    }

    try {
        // Get connection from pool
        const connection = await pool.getConnection();

        const sql = `
            UPDATE employees 
            SET phone = ?, address = ?, department = ?, role = ? 
            WHERE employeeID = ?
        `;

        // Execute the query
        const [result] = await connection.query(sql, [phone, address, department, role, employeeId]);

        // Release the connection back to the pool
        connection.release();

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Employee not found.' });
        }

        res.status(200).json({ message: '✅ Employee updated successfully.' });
    } catch (err) {
        console.error('❌ Error updating employee:', err);
        res.status(500).json({ message: 'Database error', error: err.message });
    }
});


app.get("/getEmployees/:hrId", async (req, res) => {
    const { hrId } = req.query;

    try {
        const connection = await pool.getConnection();

        let query, params;

        if (hrId) {
            // Fetch employees for specific HR
            query = `SELECT * FROM employees WHERE hrId = ?`;
            params = [hrId];
        } else {
            // Fetch all employees if hrId is not provided
            query = `SELECT * FROM employees`;
            params = [];
        }

        const [employees] = await connection.query(query, params);

        connection.release();
        res.status(200).json(employees);

    } catch (error) {
        console.error("❌ Error Fetching Employees:", error);
        res.status(500).json({ error: "Database error", details: error });
    }
});



// ✅ Employee Leave Request Submission : WORKING
app.post('/leave-request', async (req, res) => {
    const { hrId } = req.params;
    const { employeeId, leaveType, startDate, endDate, reason } = req.body;

    // Basic validation of inputs
    if (!employeeId || !leaveType || !startDate || !endDate || !reason) {
        return res.status(400).json({ message: "All fields are required." });
    }

    // Validate date range
    if (new Date(startDate) >= new Date(endDate)) {
        return res.status(400).json({ success: false, message: "Start date must be before end date" });
    }

    // Calculate the number of leave days requested
    const requestedDays = Math.ceil((new Date(endDate) - new Date(startDate)) / (1000 * 60 * 60 * 24)) + 1;
   
   
    try {
        const connection = await pool.getConnection();
        // Get total leave days taken this year
        const [leaveRecords] = await connection.query(
            "SELECT SUM(DATEDIFF(end_date, start_date) + 1) AS totalLeaveTaken FROM leave_request WHERE employeeID = ? AND YEAR(start_date) = YEAR(CURDATE()) AND status = 'Approved'",
            [employeeId]
        );
        const totalLeaveTaken = leaveRecords[0].totalLeaveTaken || 0;
        const remainingLeave = 15 - totalLeaveTaken;

        if (requestedDays > remainingLeave) {
            return res.status(400).json({ success: false, message: `You only have ${remainingLeave} leave days left.` });
        }

        // Insert the leave request into the database
        const query = 'INSERT INTO leave_request (employeeID, leave_type, start_date, end_date, reason, status, hrId) VALUES (?, ?, ?, ?, ?, "Pending",?)';
        await connection.query(query, [employeeId, leaveType, startDate, endDate, reason,hrId]);

        connection.release(); // Release the connection back to the pool

        res.status(200).json({ message: "Leave request submitted successfully!" });
    } catch (err) {
        console.error("Error submitting leave request:", err);
        res.status(500).json({ message: "Error submitting leave request." });
    }
});

//Fetch Leave Request
app.get("/leave-requests/:hrId", async (req, res) => {
    const { hrId } = req.params;

    try {
        const connection = await pool.getConnection();

        const [results] = await connection.query(
            `SELECT 
            lr.id, lr.leave_type, lr.start_date, lr.end_date, lr.reason, lr.status,
            e.name AS employee_name, e.employeeID
        FROM 
            leave_request lr
        JOIN 
            employees e ON lr.employeeID = e.employeeID
        WHERE 
            e.hrId = ?
        ORDER BY 
            lr.id DESC`,
            [hrId]
        );

        connection.release();
        res.json(results);
    } catch (error) {
        console.error("❌ Error fetching leave requests:", error);
        res.status(500).json({ success: false, message: "Database error" });
    }
});

// ✅ Route to update leave status, update used_leave, and send email
app.put("/update-leave-status", async (req, res) => {
    const { id, status } = req.body;

    // ✅ Validate input
    if (!id || !status) {
        return res.status(400).json({ success: false, message: "ID and status are required" });
    }

    const validStatuses = ["Pending", "Approved", "Rejected"];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ success: false, message: "Invalid status value" });
    }

    try {
        const connection = await pool.getConnection();

        // ✅ Fetch leave request details + employee email, name, used_leave, total_leave
        const [leaveDetails] = await connection.query(
            `SELECT lr.*, e.email, e.name, e.used_leave, e.total_leave, e.employeeID
             FROM leave_request lr
             JOIN employees e ON lr.employeeID = e.employeeID
             WHERE lr.id = ?`,
            [id]
        );

        if (leaveDetails.length === 0) {
            connection.release();
            return res.status(404).json({ success: false, message: "Leave request not found" });
        }

        const { email, name, used_leave, total_leave, employeeID, start_date, end_date } = leaveDetails[0];

        // ✅ Calculate leave duration (inclusive)
        const start = new Date(start_date);
        const end = new Date(end_date);
        const duration = Math.ceil((end - start) / (1000 * 60 * 60 * 24)) + 1;

        // ✅ Update leave_request status
        await connection.query(
            `UPDATE leave_request SET status = ? WHERE id = ?`,
            [status, id]
        );

        // ✅ If Approved, add duration to used_leave (cannot exceed total_leave)
        if (status === "Approved") {
            let newUsedLeave = used_leave + duration;
            if (newUsedLeave > total_leave) newUsedLeave = total_leave; // Cap at total_leave

            await connection.query(
                `UPDATE employees SET used_leave = ? WHERE employeeID = ?`,
                [newUsedLeave, employeeID]
            );
        }

        // ✅ Send Email Notification
        const subject = `Your Leave Request has been ${status}`;
        const message = `
            <h3>Hello ${name},</h3>
            <p>Your leave request from <strong>${start_date}</strong> to <strong>${end_date}</strong> has been <b>${status}</b> by HR.</p>
            ${status === "Approved" ? `<p><b>Duration:</b> ${duration} days have been added to your used leaves.</p>` : ''}
            <p>Your updated leave status: <b>${status}</b>.</p>
            <p>Contact HR if you have questions.</p>
            <br>
            <p>Regards,<br><b>WorkForce360 Team</b></p>
        `;

        const mailOptions = {
            from: '"WorkForce360" workforce360org@gmail.com',
            to: email,
            subject: subject,
            html: message
        };

        // ✅ Send email
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('❌ Error sending email:', error);
            } else {
                console.log('✅ Email sent:', info.response);
            }
        });

        connection.release();

        // ✅ Final success response
        res.json({ success: true, message: `Leave request ${status} successfully!` });

    } catch (error) {
        console.error("❌ Error processing leave request:", error);
        res.status(500).json({ success: false, message: "Server error", error });
    }
});


//ATTENDANCE

// ✅ Clock In : WORKING
app.post('/attendance/clock-in', async (req, res) => {
    const { employeeId } = req.body;
    if (!employeeId) return res.status(400).json({ error: 'Employee ID is required' });

    try {
        const connection = await pool.getConnection();
        
        // Check if the employee has already clocked in today
        const [existingRecord] = await connection.query(
            "SELECT * FROM attendance WHERE employee_id = ? AND DATE(clock_in_time) = CURDATE()",
            [employeeId]
        );

        if (existingRecord.length > 0) {
            return res.status(400).json({ message: "Already clocked in for today" });
        }

        // Set clock-in time and status
        const clockInTime = new Date();
        const status = clockInTime.getHours() < 10 || (clockInTime.getHours() === 10 && clockInTime.getMinutes() <= 30)
            ? 'Present' 
            : 'Late';

            await connection.query(
                "INSERT INTO attendance (employee_id, clock_in_time, status) VALUES (?, ?, ?)",
                [employeeId, clockInTime, status]
            );

            connection.release();
            res.json({ success: true, message: 'Clocked in successfully' });
    } catch (error) {
        console.error("Clock-in error:", error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// ✅ Clock Out : WORKING
app.post('/attendance/clock-out', async (req, res) => {
    const { employeeId } = req.body;
    if (!employeeId) return res.status(400).json({ error: 'Employee ID is required' });

    try {
        const connection = await pool.getConnection();

        // Check if the employee has clocked in today
        const [existingRecord] = await connection.query(
            "SELECT * FROM attendance WHERE employee_id = ? AND DATE(clock_in_time) = CURDATE() AND clock_out_time IS NULL",
            [employeeId]
        );

        if (existingRecord.length === 0) {
            return res.status(400).json({ message: "No clock-in record found for today" });
        }

        // Set clock-out time and status
        const clockOutTime = new Date();
        const status = clockOutTime.getHours() < 14 || clockOutTime.getHours() >= 23
            ? 'Absent'
            : 'Present';

        await connection.query(
            "UPDATE attendance SET clock_out_time = ?, status = ? WHERE id = ?",
            [clockOutTime, status, existingRecord[0].id]
        );
        connection.release();
        res.json({ success: true, message: 'Clocked out successfully' });
    } catch (error) {
        console.error("Clock-out error:", error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// ✅ Get Attendance Records
app.get("/attendance/:employeeId", async (req, res) => {
    const { employeeId } = req.params;
    try {
        const connection = await pool.getConnection();
        const [records] = await connection.query(
            "SELECT clock_in_time, clock_out_time, status FROM attendance WHERE employee_id = ? ORDER BY id DESC",
            [employeeId]
        );
        connection.release();
        res.json(records);
    } catch (error) {
        console.error("Fetch error:", error);
        res.status(500).json({ message: "Server error" });
    }
});

//Attendance to HR
app.get("/api/attendance/:hrId", async (req, res) => {
    const { hrId } = req.params; // ✅ Correct way to get hrId
    if (!hrId) return res.status(400).json({ message: "HR ID is required" });

    try {
        const connection = await pool.getConnection();
        const [employees] = await connection.query(
            "SELECT e.employeeID, e.name, e.department, a.date, a.status FROM employees e INNER JOIN attendance a ON e.employeeID = a.employee_Id WHERE e.hrId = ?",
            [hrId]
        );
        res.json(employees);  // Send only the array;
    } catch (error) {
        console.error("Error fetching attendance:", error);
        res.status(500).json({ message: "Internal server error" });
    }
});


// Update attendance API
app.post("/api/attendance/update", async (req, res) => {
    const { empId, status } = req.body;

    if (!empId || !status) {
        return res.status(400).json({ message: "Employee ID and status are required" });
    }

    try {
        const connection = await pool.getConnection();
        // Update attendance record in the database
        const [result] = await connection.query(
            "UPDATE attendance SET status = ? WHERE employee_Id = ?",
            [status, empId]
        );

        if (result.affectedRows > 0) {
            return res.json({ message: "Attendance updated successfully" });
        } else {
            return res.status(404).json({ message: "Attendance record not found" });
        }
    } catch (error) {
        console.error("Error updating attendance:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
});


// Route to submit an employee evaluation
app.post("/submitEvaluation", async (req, res) => {
    try {
        const { employeeId, scores } = req.body;
        if (!employeeId || !scores) {
            return res.status(400).json({ success: false, message: "Invalid input data" });
        }
        
        // Parse scores and calculate average
        const parsedScores = JSON.parse(scores);
        const averageScore = (
            (parseInt(parsedScores.workQuality) +
             parseInt(parsedScores.punctuality) +
             parseInt(parsedScores.communication)) / 3
        ).toFixed(1);

        // Use pool instead of connection
        const query = "INSERT INTO evaluations (employeeId, scores, average_score, created_at) VALUES (?, ?, ?, NOW())";
        await pool.query(query, [employeeId, scores, averageScore]);

        res.json({ success: true, message: "Evaluation submitted successfully" });
    } catch (error) {
        console.error("Error submitting evaluation:", error);
        res.status(500).json({ success: false, message: "Failed to submit evaluation" });
    }
});

app.get("/get-evaluations/:employeeId", async (req, res) => {
    try {
        const { employeeId } = req.params;

        if (!employeeId) {
            return res.status(400).json({ success: false, message: "Employee ID is required" });
        }

        const sql = "SELECT average_score, created_at FROM evaluations WHERE employeeId = ? ORDER BY created_at DESC LIMIT 1";
        
        // Corrected database query with async/await
        const [results] = await pool.query(sql, [employeeId]);

        if (results.length === 0) {
            return res.json({ success: true, evaluations: [] });
        }

        res.json({ success: true, evaluations: results });
    } catch (error) {
        console.error("Error fetching evaluations:", error);
        res.status(500).json({ success: false, message: "Failed to fetch evaluations" });
    }
});

// Fetch employees under a specific HR
app.get("/getAllEmployees", async (req, res) => {
    try {
        const { hrId } = req.query;

        if (!hrId) {
            return res.status(400).json({ success: false, message: "HR ID is required" });
        }

        const connection = await pool.getConnection();
        const [results] = await connection.query("SELECT employeeID, name FROM employees WHERE hrId = ?", [hrId]);
        connection.release();

        res.json({ success: true, employees: results });
    } catch (error) {
        console.error("Error fetching employees:", error);
        res.status(500).json({ success: false, message: "Failed to fetch employees" });
    }
});

app.get("/leaveBalance/:employeeId", async (req, res) => {
    const { employeeId } = req.params;
    try {
        const connection = await pool.getConnection();
        const [leaveRecords] = await connection.query(
            "SELECT total_leave - used_leave AS remainingLeaves, total_leave FROM employees WHERE employeeID = ?",
            [employeeId]
        );
        connection.release();

        if (leaveRecords.length === 0) {
            return res.status(404).json({ success: false, message: "Employee not found" });
        }

        res.json({ success: true, remainingLeaves: leaveRecords[0].remainingLeaves, totalLeaves: leaveRecords[0].total_leave });
    } catch (error) {
        console.error("Error fetching leave balance:", error);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

// ✅ Start the server
app.listen(port, () => {
    console.log(`🚀 Server running at http://localhost:${port}`);
});
