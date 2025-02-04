import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import crypto from "crypto";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

mongoose.connect(process.env.MONGO_URI);

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  username: { type: String, required: true, unique: true }, // Added username for login matching
  isVerified: { type: Boolean, default: false }, // User starts as unverified
  verificationToken: { type: String, default: null },
});
const User = mongoose.model("User", UserSchema);

const CallbackSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  data: Object,
  createdAt: { type: Date, default: Date.now },
});
const Callback = mongoose.model("Callback", CallbackSchema);

app.use(bodyParser.json());
app.use(cors());
app.use(morgan("dev"));
app.use(cookieParser()); // Enable cookie parsing middleware

// User Registration
// Setup email transporter (Replace with your SMTP details)
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER, // Your email
    pass: process.env.EMAIL_PASS, // Your email password
  },
});

// User Registration
app.post("/api/auth/register", async (req, res) => {
  const { email, password, username } = req.body;

  try {
    if (!email || !password || !username) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res
        .status(400)
        .json({ error: "Email or username is already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Generated hash:", hashedPassword); // Log the hash during registration

    const verificationToken = crypto.randomBytes(32).toString("hex");

    const user = new User({
      email,
      password: hashedPassword,
      username,
      isVerified: false, // User starts as unverified
      verificationToken,
    });

    await user.save();

    // Send verification email
    const verificationLink = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify Your Account",
      html: `
    <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f4f4f4;">
      <div style="max-width: 500px; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); margin: auto;">
        <h2 style="color: #333;">Welcome to Our Platform! 🎉</h2>
        <p style="color: #555;">You're almost there! Click the button below to verify your email and activate your account.</p>
        <a href="${verificationLink}" target="_blank" style="display: inline-block; padding: 12px 24px; color: white; background-color: #007BFF; text-decoration: none; font-size: 16px; border-radius: 5px; font-weight: bold; margin-top: 10px;">
          Verify My Account
        </a>
        <p style="color: #777; margin-top: 10px;">If the button doesn’t work, <a href="${verificationLink}" target="_blank">click here</a>.</p>
      </div>
    </div>
  `,
    });

    res
      .status(201)
      .json({ message: "User registered. Please verify your email." });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/auth/verify/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return res
        .status(400)
        .json({ error: "Invalid or expired verification token" });
    }

    // Mark user as verified
    user.isVerified = true;
    user.verificationToken = null; // Remove the token after use
    await user.save();

    // Generate and return an auth token (auto-login)
    const authToken = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      {
        expiresIn: "24h",
      }
    );

    res.cookie("token", authToken, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    }); // 24 hours

    // Send welcome email
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Welcome to Our Platform! 🎉",
      html: `
        <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f4f4f4;">
          <div style="max-width: 500px; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); margin: auto;">
            <h2 style="color: #333;">Welcome, ${user.username}! 🎉</h2>
            <p style="color: #555;">Your account has been successfully verified. Welcome to our platform!</p>
            <p style="color: #555;">Here are a few things you can do now:</p>
            <ul style="text-align: left; color: #555;">
              <li>Explore your dashboard</li>
              <li>Update your profile</li>
              <li>Start using our services</li>
            </ul>
            <p style="color: #777; margin-top: 10px;">We're excited to have you on board!</p>
          </div>
        </div>
      `,
    });

    res.status(200).json({ message: "Account verified!", token: authToken });
  } catch (error) {
    console.error("Error verifying user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/auth/resend-verification-email", async (req, res) => {
  try {
    const { email } = req.body; // Get email from the request body
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Resend the verification email
    const verificationLink = `${process.env.FRONTEND_URL}/verify/${user.verificationToken}`;
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Verify Your Account",
      html: `
        <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f4f4f4;">
          <div style="max-width: 500px; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); margin: auto;">
            <h2 style="color: #333;">Welcome to Our Platform! 🎉</h2>
            <p style="color: #555;">Click the button below to verify your email and activate your account.</p>
            <a href="${verificationLink}" target="_blank" style="display: inline-block; padding: 12px 24px; color: white; background-color: #007BFF; text-decoration: none; font-size: 16px; border-radius: 5px; font-weight: bold; margin-top: 10px;">
              Verify My Account
            </a>
            <p style="color: #777; margin-top: 10px;">If the button doesn’t work, <a href="${verificationLink}" target="_blank">click here</a>.</p>
          </div>
        </div>
      `,
    });

    res.status(200).json({ message: "Verification email resent successfully" });
  } catch (error) {
    console.error("Error resending verification email:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/auth/check-verification", async (req, res) => {
  try {
    const { email } = req.query; // Get email from the query parameters
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json({ isVerified: user.isVerified });
  } catch (error) {
    console.error("Error checking verification status:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// User Login
app.post("/api/auth/login", async (req, res) => {
  const { identifier, password } = req.body;

  // Validate input (basic validation can also be improved further with express-validator)
  if (!identifier || !password) {
    return res
      .status(400)
      .json({ error: "Please provide both an identifier and password." });
  }

  console.warn(password);

  try {
    // Check if either email or username is provided, then query for either one.
    const user = await User.findOne({
      $or: [{ username: identifier }, { email: identifier }],
    });

    // User not found
    if (!user) {
      console.warn(
        `Login failed: No user found with identifier "${identifier}"`
      );
      return res.status(401).json({
        error: "Invalid Username or Email. Please try again.",
        success: false,
      });
    }

    // Compare password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);
    console.log("Is password valid:", isPasswordValid); // Log result during login

    if (!isPasswordValid) {
      console.warn(
        `Login failed: Invalid password for user "${user.username}"`
      );
      return res
        .status(401)
        .json({ error: "Invalid Password. Please try again." });
    }

    // Check if user is verified
    if (!user.isVerified) {
      console.info(`Login attempt by unverified user "${user.username}"`);
      return res.status(403).json({
        error: "Please verify your email before logging in.",
      });
    }

    // Create a JWT token
    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        username: user.username,
      },
      JWT_SECRET,
      { expiresIn: "24h" } // 24-hour expiry
    );

    // Set the token in cookies (httpOnly ensures it's not accessible via JavaScript)
    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 24 hours in milliseconds
      secure: process.env.NODE_ENV === "production", // Send only over HTTPS in production
      sameSite: "strict", // Prevent CSRF attacks
    });

    // Send login notification email
    const loginTime = new Date().toLocaleString();
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: user.email,
      subject: "Successful Login Notification",
      html: `
        <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px; background-color: #f4f4f4;">
          <div style="max-width: 500px; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2); margin: auto;">
            <h2 style="color: #333;">Hello, ${user.username}! 👋</h2>
            <p style="color: #555;">You have successfully logged into your account at <strong>${loginTime}</strong>.</p>
            <p style="color: #555;">If this was not you, please contact us immediately.</p>
            <p style="color: #777; margin-top: 10px;">Thank you for using our platform!</p>
          </div>
        </div>
      `,
    });

    // Send the token and user info as a response
    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    // Log the full error on the server side
    console.error("Error during login process:", error);

    // Send generic error response to the client without exposing details
    res.status(500).json({
      error:
        "An error occurred while trying to log in. Please try again later.",
    });
  }
});

app.get("/api/auth/validate", async (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1]; // Extract token from headers

  if (!token) {
    // If no token is provided in the request
    return res.status(400).json({ error: "No token provided" });
  }

  try {
    // Verify token (e.g., using JWT)
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      // Use the secret key here
      if (err) {
        // Handle errors when token verification fails
        if (err.name === "TokenExpiredError") {
          return res.status(401).json({ error: "Token has expired" });
        } else if (err.name === "JsonWebTokenError") {
          return res.status(401).json({ error: "Invalid token" });
        } else {
          return res
            .status(500)
            .json({ error: "Failed to authenticate token" });
        }
      }

      // Here, `decoded` contains the payload from the token
      const { userId, email, username } = decoded;

      // Fetch the user from the database using the userId from the decoded token
      try {
        const user = await User.findById(userId); // Assuming `User` is your database model
        if (!user) {
          return res.status(404).json({ error: "User not found" });
        }

        // If everything is fine, send the user data back
        res.json({ user: { email, username, userId } });
      } catch (dbError) {
        console.error("Database error:", dbError); // Log DB error for debugging
        res.status(500).json({ error: "Database error while fetching user" });
      }
    });
  } catch (error) {
    // Catch any unexpected errors during the token verification process
    console.error("Unexpected error during token validation:", error); // Log unexpected errors for debugging
    res
      .status(500)
      .json({ error: "Unexpected server error during token validation" });
  }
});;

// Middleware to authenticate users
const authenticate = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.split(" ")[1];
    if (!token) return res.status(401).json({ error: "Unauthorized" });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ error: "Invalid user" });
    }

    req.user = { userId: user._id, username: user.username };
    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// M-Pesa Callback Handler
app.post("/api/mpesa/callback/:username", authenticate, async (req, res) => {
  try {
    const { username } = req.params;

    // Check if the user exists in the database
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Ensure the authenticated user matches the username in the URL
    if (req.user.username !== username) {
      return res.status(403).json({ error: "Unauthorized user" });
    }

    const callbackData = req.body;
    if (!callbackData?.Body?.stkCallback) {
      return res.status(400).json({ error: "Invalid callback data" });
    }

    const {
      stkCallback: { ResultCode, ResultDesc, CallbackMetadata },
    } = callbackData.Body;

    // Extract metadata
    const metadata =
      CallbackMetadata?.Item?.reduce((acc, item) => {
        acc[item.Name] = item.Value;
        return acc;
      }, {}) || {};

    // Save the callback data
    await Callback.create({
      userId: req.user.userId,
      username: req.user.username,
      data: {
        ResultCode,
        ResultDesc,
        metadata: {
          Amount: metadata.Amount,
          MpesaReceiptNumber: metadata.MpesaReceiptNumber,
          Balance: metadata.Balance,
          TransactionDate: metadata.TransactionDate,
          PhoneNumber: metadata.PhoneNumber,
        },
      },
    });

    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Callback processing error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Display Latest Callback Logs (accessible only for authenticated users)
// Display Latest Callback Logs (accessible only for authenticated users)
app.get("/api/mpesa/callback/logs/:userId", authenticate, async (req, res) => {
  try {
    const { userId } = req.params;

    // Check if the authenticated user's ID matches the userId in the URL
    if (req.user.userId.toString() !== userId) {
      return res.status(403).json({ error: "Unauthorized access to logs" });
    }

    // Fetch logs for the specified user
    const logs = await Callback.find({ userId })
      .sort({ createdAt: -1 }) // Sort by most recent first
      .limit(10); // Limit the number of logs to show

    if (logs.length === 0) {
      return res.status(404).json({ message: "No logs found for this user" });
    }

    res.json({ logs });
  } catch (error) {
    console.error("Error fetching logs:", error);
    res.status(500).json({ error: "Error fetching logs" });
  }
});

// Delete one log
app.get("/api/mpesa/callback/logs/:userId", authenticate, async (req, res) => {
  try {
    const { userId } = req.params;
    const { page = 1, limit = 10 } = req.query;

    if (req.user.userId.toString() !== userId) {
      return res.status(403).json({ error: "Unauthorized access to logs" });
    }

    const logs = await Callback.find({ userId })
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit);

    const totalLogs = await Callback.countDocuments({ userId });
    const totalPages = Math.ceil(totalLogs / limit);

    res.json({ logs, totalPages });
  } catch (error) {
    console.error("Error fetching logs:", error);
    res.status(500).json({ error: "Error fetching logs" });
  }
});

// Delete all logs for a user
app.delete(
  "/api/mpesa/callback/logs/:userId",
  authenticate,
  async (req, res) => {
    try {
      const { userId } = req.params;

      // Check if the authenticated user's ID matches the userId in the URL
      if (req.user.userId.toString() !== userId) {
        return res.status(403).json({ error: "Unauthorized access to logs" });
      }

      // Delete all logs for the specified user
      const result = await Callback.deleteMany({ userId });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "No logs found for this user" });
      }

      res.status(200).json({ message: "All logs deleted successfully" });
    } catch (error) {
      console.error("Error deleting logs:", error);
      res.status(500).json({ error: "Error deleting logs" });
    }
  }
);

// Delete selected logs based on an array of logIds
app.delete(
  "/api/mpesa/callback/logs/:userId/selected",
  authenticate,
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { logIds } = req.body; // Expecting an array of logIds to be sent in the body

      // Check if the authenticated user's ID matches the userId in the URL
      if (req.user.userId.toString() !== userId) {
        return res.status(403).json({ error: "Unauthorized access to logs" });
      }

      // Delete the selected logs
      const result = await Callback.deleteMany({
        _id: { $in: logIds },
        userId,
      });

      if (result.deletedCount === 0) {
        return res.status(404).json({ message: "No logs found to delete" });
      }

      res.status(200).json({ message: "Selected logs deleted successfully" });
    } catch (error) {
      console.error("Error deleting selected logs:", error);
      res.status(500).json({ error: "Error deleting selected logs" });
    }
  }
);

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
