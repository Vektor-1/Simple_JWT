import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import { createClient } from "redis";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";

// Setup Express app
const app = express();
app.use(express.json());
app.use(cors()); // Enable CORS

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI!)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  username: String,
  password: String
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

// Generate JWT Token
const generateToken = (userId: string) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET!, { expiresIn: "1h" });
};

// Register User
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = await User.create({ username, password: hashedPassword });

  res.json({ message: "User registered", userId: newUser._id });
});

// Login User
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password required" });

  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: "Invalid credentials" });

  const token = generateToken(user._id.toString());

  // Store token in Redis
  await redisClient.setEx(`auth:${user._id}`, 3600, token); // 1 hour expiry

  res.json({ message: "Login successful", token });
});

// Protected Route
app.get("/profile", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);
    
    // Check Redis for valid token
    const redisToken = await redisClient.get(`auth:${decoded.userId}`);
    if (!redisToken) return res.status(401).json({ error: "Session expired, login again" });

    const user = await User.findById(decoded.userId);
    res.json({ username: user?.username });
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Logout
app.post("/logout", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(400).json({ error: "No token provided" });

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);
    
    // Remove session from Redis
    await redisClient.del(`auth:${decoded.userId}`);

    res.json({ message: "Logged out successfully" });
  } catch (err) {
    res.status(400).json({ error: "Invalid token" });
  }
});

// Start Server
app.listen(3000, () => console.log("Server running on port 3000"));
