import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import { createClient } from "redis";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import ratelimit from "express-rate-limit";
import crypto from "crypto";
import twilio from "twilio";
import nodemon from "nodemon";
import nodemailer from "nodemailer";

const app = express();
app.use(express.json());
app.use(cors());

// Rate Limit
const limiter = ratelimit({
    windowMs: 15 * 60 * 1000, 
    max: 100, 
    message: "Too many requests from this IP, please try again later.",
});
app.use(limiter);

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI!)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  phone: {type: String, unique: true, required: true},
  email: { type: String, unique: true, required: true },
  verified: { type: Boolean, default: false }
});
const User = mongoose.model("User", userSchema);

// Redis Connection
const redisClient = createClient({
  socket: {
    host: process.env.REDIS_HOST,
    port: Number(process.env.REDIS_PORT),
  },
});
redisClient.connect();

const twilioClient = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH_TOKEN);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

const generateOTP = () => crypto.randomInt(100000, 999999).toString();

// Generate Tokens
const generateToken = (userId: string) => jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: "1h" });
const generateRefreshToken = (userId: string) => jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: "7d" });

const sendOTP = async (phone: string, email: string, otp: string) => {
  try {
    if (email) {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your OTP Code",
        text: `Your OTP is: ${otp}`,
      });
    }
    if (phone) {
      await twilioClient.messages.create({
        body: `Your OTP is: ${otp}`,
        from: process.env.TWILIO_PHONE,
        to: phone,
      });
    }
  } catch(err) {
    console.error("Error sending OTP:", err);
  }
};

// Register User
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  const hashedPassword = await bcrypt.hash(password, 12);
  const newUser = await User.create({ username, password: hashedPassword });

  res.json({ message: "User registered", userId: newUser._id });
});

app.post("/request-otp", async (req, res) => {
  const { email, phone } = req.body;
  if (!email && !phone) return res.status(400).json({ error: "Email or phone required" });
  
  const otp = generateOTP();
  const key = email ? `otp:${email}` : `otp:${phone}`;
  await redisClient.setEx(key, 900, otp); // 15 min expiry

  await sendOTP(email, phone, otp);
  res.json({ message: "OTP sent" });
})

app.post("/verify-otp", async (req, res) => {
  const { email, phone, otp } = req.body;
  if (!email && !phone || !otp) return res.status(400).json({ error: "Missing fields" });

  const key = email ? `otp:${email}` : `otp:${phone}`;
  const storedOTP = await redisClient.get(key);

  if (storedOTP === otp) {
    await redisClient.del(key);
    await User.updateOne({ _id: newUser._id }, { verified: true });
    res.json({ message: "OTP verified" });
  } else {
    res.status(400).json({ error: "Invalid or expired OTP" });
  }
});

// Login User
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  const user = await User.findOne({ username }).lean().explain();
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = generateToken(user._id.toString());
  const refreshToken = generateRefreshToken(user._id.toString());

  // Store session in Redis
  const sessionId = crypto.randomUUID();
  await redisClient.setEx(`session:${user._id}`, 3600, sessionId); 

  // Store refresh token
  await redisClient.setEx(`refreshToken:${user._id}`, 604800, refreshToken);

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
  });

  res.json({ message: "Login successful", token });
});

// Protected Route
app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);
    
    // Check Redis session
    const redisSession = await redisClient.get(`session:${decoded.userId}`);
    if (!redisSession) return res.status(401).json({ error: "Session expired, login again" });

    const user = await User.findById(decoded.userId).lean().explain();
    res.json({ username: user?.username });
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

app.get("/users", async (req, res) => {
  try {
    const users = await User.find({});
    console.log("All Users:", users);
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

// Logout
app.post("/logout", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(400).json({ error: "No token provided" });

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);
    
    // Remove session & refresh token from Redis
    await redisClient.del(`session:${decoded.userId}`);
    await redisClient.del(`refreshToken:${decoded.userId}`);

    res.json({ message: "Logged out successfully" });
  } catch (err) {
    res.status(400).json({ error: "Invalid token" });
  }
});

// Start Server
app.listen(3000, () => console.log("Server running on port 3000"));
