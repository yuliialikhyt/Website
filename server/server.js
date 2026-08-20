require("dotenv").config();

const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const authRoutes = require("./routes/auth");

const app = express();

app.use(express.json());
app.use(cookieParser());

// Allow the front-end origin to send/receive cookies.
// Update FRONTEND_ORIGIN in .env to match where login.html/create-account.html are served from.
app.use(cors({
    origin: process.env.FRONTEND_ORIGIN || "http://localhost:5500",
    credentials: true,
}));

app.use("/api/auth", authRoutes);

app.get("/api/health", (req, res) => {
    res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Martel backend listening on port ${PORT}`);
});