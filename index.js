import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import cors from "cors";
import morgan from "morgan";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Allowed CORS origins
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:55000",
  "http://yourfrontend.com",
];

// Middleware
app.use(bodyParser.json());
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(morgan("dev")); // Logs incoming requests

/**
 * @desc M-Pesa Callback Handler
 * @route POST /api/mpesa/callback
 */

/**
 * @desc Handle M-Pesa Callback
 * @route POST /api/mpesa/callback
 * @access public
 */
app.post("/api/mpesa/callback", (req, res) => {
  try {
    const callbackData = req.body;
    console.log("Callback Data:", callbackData);

    // Validate the callback data
    if (!callbackData || !callbackData.Body || !callbackData.Body.stkCallback) {
      console.error("Invalid callback data:", callbackData);
      return res
        .status(400)
        .json({ success: false, error: "Invalid callback data" });
    }

    const {
      Body: {
        stkCallback: { ResultCode, ResultDesc, CallbackMetadata },
      },
    } = callbackData;

    if (ResultCode === "0") {
      // Payment was successful
      console.log("Payment successful:", CallbackMetadata);

      // Extract transaction details from CallbackMetadata
      const metadata = CallbackMetadata.Item.reduce((acc, item) => {
        acc[item.Name] = item.Value;
        return acc;
      }, {});

      const { Amount, MpesaReceiptNumber, PhoneNumber, TransactionDate } =
        metadata;

      // Update the database (e.g., mark payment as paid)
      // Example: await PaymentModel.updatePaymentStatus(MpesaReceiptNumber, "Paid");

      console.log("Transaction Details:", {
        amount: Amount,
        receiptNumber: MpesaReceiptNumber,
        phoneNumber: PhoneNumber,
        transactionDate: TransactionDate,
      });
    } else {
      // Payment failed
      console.log("Payment failed:", ResultDesc);

      // Update the database (e.g., mark payment as failed)
      // Example: await PaymentModel.updatePaymentStatus(null, "Failed");
    }

    // Respond to M-Pesa
    res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error processing callback:", error);
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

/**
 * @desc Test Route
 * @route GET /
 */
app.get("/", (req, res) => {
  res
    .status(200)
    .json({ message: "The mpesa callback was successfully called. 😂" });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("Server Error:", err.message);
  res.status(500).json({ message: "Internal Server Error" });
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
