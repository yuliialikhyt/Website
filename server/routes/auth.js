const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("../db/pool");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET;
const SALT_ROUNDS = 12;
const COOKIE_NAME = "martel_session";

const isProd = process.env.NODE_ENV === "production";

function setSessionCookie(res, userId) {
    const token = jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: "7d" });
    res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: isProd,       // only over HTTPS in production
        sameSite: "lax",
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
}

function isValidEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

/*
 * POST /api/auth/signup
 * body: { fullName, email, password }
 */
router.post("/signup", async (req, res) => {
    try {
        const { fullName, email, password } = req.body;

        if (!fullName || !fullName.trim()) {
            return res.status(400).json({ error: "Full name is required." });
        }
        if (!email || !isValidEmail(email)) {
            return res.status(400).json({ error: "A valid email is required." });
        }
        if (!password || password.length < 8) {
            return res.status(400).json({ error: "Password must be at least 8 characters." });
        }

        const existing = await pool.query(
            "SELECT id FROM users WHERE LOWER(email_address) = LOWER($1)",
            [email]
        );
        if (existing.rows.length > 0) {
            // Same message whether the email exists or is malformed-but-taken,
            // to avoid confirming account existence to an attacker.
            return res.status(409).json({ error: "An account with that email already exists." });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        const result = await pool.query(
            `INSERT INTO users (first_name, email_address, password)
             VALUES ($1, $2, $3)
             RETURNING id, first_name, email_address, created_at`,
            [fullName.trim(), email.trim(), passwordHash]
        );

        const user = result.rows[0];
        setSessionCookie(res, user.id);

        return res.status(201).json({
            id: user.id,
            fullName: user.full_name,
            email: user.email,
        });

    } catch (err) {
        console.error("Signup error:", err);
        return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
});

/*
 * POST /api/auth/login
 * body: { email, password }
 */
router.post("/login", async (req, res) => {
    try {
        const { email, password_decrypted } = req.body;

        if (!email || !password_decrypted) {
            return res.status(400).json({ error: "Email and password are required." });
        }

        const result = await pool.query(
            "SELECT id, first_name, email_address, password FROM users WHERE LOWER(email_address) = LOWER($1)",
            [email]
        );

        // Deliberately generic error — don't reveal whether the email exists.
        const genericError = () =>
            res.status(401).json({ error: "That email and password combination didn't work." });

        if (result.rows.length === 0) {
            return genericError();
        }

        const user = result.rows[0];
        const matches = await bcrypt.compare(password_decrypted, user.password);

        if (!matches) {
            return genericError();
        }

        setSessionCookie(res, user.id);

        return res.json({
            id: user.id,
            fullName: user.first_name,
            email: user.email_address,
        });

    } catch (err) {
        console.error("Login error:", err);
        return res.status(500).json({ error: "Something went wrong. Please try again." });
    }
});

/*
 * POST /api/auth/logout
 */
router.post("/logout", (req, res) => {
    res.clearCookie(COOKIE_NAME);
    return res.status(204).send();
});

/*
 * GET /api/auth/me
 * Returns the logged-in user based on the session cookie, or 401.
 */
router.get("/me", async (req, res) => {
    try {
        const token = req.cookies[COOKIE_NAME];
        if (!token) {
            return res.status(401).json({ error: "Not logged in." });
        }

        let payload;
        try {
            payload = jwt.verify(token, JWT_SECRET);
        } catch {
            return res.status(401).json({ error: "Session expired." });
        }

        const result = await pool.query(
            "SELECT id, first_name, email_address FROM users WHERE id = $1",
            [payload.sub]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({ error: "Not logged in." });
        }

        const user = result.rows[0];
        return res.json({
            id: user.id,
            fullName: user.full_name,
            email: user.email,
        });

    } catch (err) {
        console.error("Me error:", err);
        return res.status(500).json({ error: "Something went wrong." });
    }
});

module.exports = router;