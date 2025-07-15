const express = require("express");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const cors = require("cors");
const { MongoClient } = require("mongodb");
const getRawBody = require("raw-body"); // Add raw-body for fallback

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI =
  process.env.MONGODB_URI ||
  "mongodb+srv://harshdvadhavana26:harshdv007@try.j3wxapq.mongodb.net/tradingview_bot?retryWrites=true&w=majority";
const DB_NAME = "tradingview_bot";

// MongoDB Client
let db;

async function connectToMongoDB() {
  const client = new MongoClient(MONGODB_URI, { useUnifiedTopology: true });
  try {
    await client.connect();
    console.log("Connected to MongoDB");
    db = client.db(DB_NAME);
  } catch (error) {
    console.error("Failed to connect to MongoDB:", error.message);
    process.exit(1);
  }
}

// Connect to MongoDB when the server starts
connectToMongoDB();

// Middleware
app.use(async (req, res, next) => {
  // Capture raw body for fallback
  try {
    req.rawBody = await getRawBody(req, {
      length: req.headers["content-length"],
      limit: "1mb",
      encoding: "utf8",
    });
    next();
  } catch (error) {
    console.error("Error capturing raw body:", error.message);
    return res.status(400).json({ error: "Invalid request body" });
  }
});
app.use(express.text({ type: ["text/plain", "text/*"] }));
app.use(express.json({ type: ["application/json", "application/*+json"] }));
app.use(express.urlencoded({ extended: true }));
app.use(
  cors({
    origin: process.env.FRONTEND_URL || "https://xalgotelegram.netlify.app",
    credentials: true,
  })
);

// Session middleware
const sessions = new Map();
function sessionMiddleware(req, res, next) {
  const sessionId =
    req.headers["x-session-id"] || crypto.randomBytes(16).toString("hex");
  req.sessionId = sessionId;
  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {});
  }
  req.session = sessions.get(sessionId);
  res.setHeader("X-Session-ID", sessionId);
  next();
}
app.use(sessionMiddleware);

class TelegramService {
  constructor(botToken) {
    this.botToken = botToken;
    this.baseUrl = `https://api.telegram.org/bot${botToken}`;
  }

  async verifyBotToken() {
    try {
      const response = await axios.get(`${this.baseUrl}/getMe`, {
        timeout: 10000,
      });
      return response.status === 200 && response.data.ok
        ? response.data.result
        : null;
    } catch (error) {
      console.error("Error verifying bot token:", error.message);
      return null;
    }
  }

  async sendMessage(chatId, text, parseMode = null) {
    try {
      const trimmedText =
        text.length > 4000 ? text.substring(0, 4000) + "..." : text;
      const payload = { chat_id: chatId, text: trimmedText };
      if (parseMode) payload.parse_mode = parseMode;
      console.log("Sending Telegram message:", payload);
      const response = await axios.post(
        `${this.baseUrl}/sendMessage`,
        payload,
        { timeout: 10000 }
      );
      console.log(`Sent message to chat ${chatId}:`, trimmedText);
      return response.status === 200;
    } catch (error) {
      console.error("Error sending message:", error.message);
      return false;
    }
  }

  async setWebhook(webhookUrl) {
    try {
      const response = await axios.post(
        `${this.baseUrl}/setWebhook`,
        {
          url: webhookUrl,
          allowed_updates: ["message", "channel_post"],
        },
        { timeout: 10000 }
      );
      console.log(`Webhook set successfully: ${webhookUrl}`);
      return response.status === 200;
    } catch (error) {
      console.error("Error setting webhook:", error.message);
      return false;
    }
  }

  formatTradingViewAlert(alertData, contentType) {
    try {
      console.log("formatTradingViewAlert input:", { alertData, contentType });

      if (alertData === null || alertData === undefined) {
        return "📊 TradingView Alert: No data received";
      }

      if (contentType.includes("text/plain") || typeof alertData === "string") {
        const textData =
          typeof alertData === "string" ? alertData : String(alertData);
        console.log("Processing plain text alert:", textData);
        return `📊 TradingView Alert\n\n${textData.trim() || "Empty message"}`;
      }

      if (
        contentType.includes("application/json") ||
        typeof alertData === "object"
      ) {
        try {
          const formatted = JSON.stringify(alertData, null, 2);
          return `📊 TradingView Alert\n\n\`\`\`json\n${formatted}\n\`\`\``;
        } catch (error) {
          console.error("Error formatting JSON:", error.message);
          return `📊 TradingView Alert: Malformed JSON data: ${JSON.stringify(
            alertData
          )}`;
        }
      }

      return `📊 TradingView Alert: Unsupported data format: ${String(
        alertData
      )}`;
    } catch (error) {
      console.error("Error processing alert:", error.message);
      return `📊 TradingView Alert: Error processing data: ${String(
        alertData
      )}`;
    }
  }
}

function generateAuthCommand(botUsername, userId, alertType = "personal") {
  if (alertType === "channel") {
    const unique_code = uuidv4().substring(0, 8).toUpperCase();
    return `auth ${unique_code}`;
  } else {
    const secret =
      process.env.HMAC_SECRET || "3HKlcLqdkJmvjhoAf8FnYzr4Ua6QBWtG";
    const data = `${userId}`;
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(data);
    const encodedData = hmac.digest("base64");
    return `/auth@${botUsername} ${encodedData}`;
  }
}

function flashMessage(req, message, type = "success") {
  if (!req.session.flash) req.session.flash = [];
  req.session.flash.push({ message, type });
}

function getFlashMessages(req) {
  const messages = req.session.flash || [];
  req.session.flash = [];
  return messages;
}

// API Routes
app.get("/api", (req, res) => {
  res.json({ flashMessages: getFlashMessages(req) });
});

app.post("/api/setup", async (req, res) => {
  try {
    // const { bot_token, alert_type } = req.body;
    console.log(req.body);
    const bot_token = req.body.bot_token;
    const alert_type = req.body.alert_type;
    console.log("alert type ", alert_type, "bot token ", bot_token);
    if (!bot_token || !bot_token.trim()) {
      flashMessage(req, "Bot token is required", "error");
      return res.status(400).json({ error: "Bot token is required" });
    }

    const telegramService = new TelegramService(bot_token.trim());
    const botInfo = await telegramService.verifyBotToken();
    if (!botInfo) {
      flashMessage(
        req,
        "Invalid bot token. Please check your token and try again.",
        "error"
      );
      return res.status(400).json({ error: "Invalid bot token" });
    }

    let userId;
    let existingUser;
    let attempts = 0;
    const maxAttempts = 10;

    do {
      const userCount = await db.collection("users").countDocuments();
      userId = userCount + 1;
      existingUser = await db.collection("users").findOne({ id: userId });
      attempts++;
      if (attempts > maxAttempts) {
        flashMessage(req, "Unable to assign a unique user ID.", "error");
        return res
          .status(500)
          .json({ error: "Unable to assign a unique user ID" });
      }
    } while (existingUser);

    const secretKey = uuidv4();
    const botUsername = botInfo.username || "unknown";
    const authCommand = generateAuthCommand(botUsername, userId, alert_type);

    const userData = {
      id: userId,
      botToken: bot_token.trim(),
      botUsername,
      secretKey,
      authCommand,
      alertType: alert_type || "personal",
      chatId: null,
      createdAt: new Date(),
    };

    console.log("Inserting user:", userData);
    await db.collection("users").insertOne(userData);

    const protocol = req.get("X-Forwarded-Proto") || req.protocol;
    const host = req.get("Host");
    const webhookUrl = `${protocol}://${host}/webhook/telegram/${userId}`;
    await telegramService.setWebhook(webhookUrl);

    flashMessage(req, "Bot configured successfully!", "success");
    res.json({ redirect: `/dashboard/${userId}` });
  } catch (error) {
    console.error("Error in setup:", error.message);
    flashMessage(req, "An error occurred while setting up the bot", "error");
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/dashboard/:userId", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const userData = await db.collection("users").findOne({ id: userId });

    if (!userData) {
      return res.status(404).json({ error: "User not found" });
    }

    const userAlerts = await db
      .collection("alerts")
      .find({ userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .toArray();
    const protocol = req.get("X-Forwarded-Proto") || req.protocol;
    const host = req.get("Host");
    const webhookUrl = `${protocol}://${host}/webhook/tradingview/${userId}/${userData.secretKey}`;

    res.json({
      flashMessages: getFlashMessages(req),
      userData,
      recentAlerts: userAlerts,
      webhookUrl,
    });
  } catch (error) {
    console.error("Error in dashboard:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/webhook/tradingview/:userId/:secretKey", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const secretKey = req.params.secretKey;
    const userData = await db.collection("users").findOne({ id: userId });

    if (!userData || userData.secretKey !== secretKey) {
      console.log(
        `Unauthorized access: userId=${userId}, secretKey=${secretKey}`
      );
      return res.status(401).json({ error: "Unauthorized" });
    }

    const contentType = (
      req.headers["content-type"] || "unknown"
    ).toLowerCase();
    console.log("Raw req.body:", req.body);
    console.log(
      `Received TradingView alert for user ${userId}, Content-Type: ${contentType}`
    );

    let webhookData;
    if (contentType.includes("application/json")) {
      webhookData = req.body;
    } else if (contentType.includes("text/plain")) {
      webhookData =
        typeof req.body === "string"
          ? req.body
          : String(req.body || req.rawBody || "");
      console.log("Processed text/plain data:", webhookData);
    } else {
      webhookData = String(req.body || req.rawBody || "");
      console.warn(
        `Unsupported Content-Type: ${contentType}, treating as raw data`
      );
    }

    if (!userData.chatId) {
      const errorMsg =
        "Chat not configured. Please complete authentication first.";
      await db.collection("alerts").insertOne({
        userId,
        webhookData,
        contentType,
        sentSuccessfully: false,
        createdAt: new Date(),
        errorMessage: errorMsg,
      });
      return res.status(400).json({ error: errorMsg });
    }

    const telegramService = new TelegramService(userData.botToken);
    const formattedMessage = telegramService.formatTradingViewAlert(
      webhookData,
      contentType
    );
    const success = await telegramService.sendMessage(
      userData.chatId,
      formattedMessage.length > 4000
        ? formattedMessage.substring(0, 4000) + "..."
        : formattedMessage,
      contentType.includes("json") ? "Markdown" : null
    );

    await db.collection("alerts").insertOne({
      userId,
      webhookData,
      contentType,
      formattedMessage,
      sentSuccessfully: success,
      createdAt: new Date(),
      errorMessage: success ? null : "Failed to send message",
    });

    return success
      ? res.json({ status: "success" })
      : res.status(500).json({ error: "Failed to send alert" });
  } catch (error) {
    console.error("Error in tradingview webhook:", error.message);
    await db.collection("alerts").insertOne({
      userId: parseInt(req.params.userId),
      webhookData: req.body || String(req.rawBody || ""),
      contentType: req.headers["content-type"] || "unknown",
      sentSuccessfully: false,
      createdAt: new Date(),
      errorMessage: error.message,
    });
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/webhook/telegram/:userId", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    console.log(`Received Telegram update for userId ${userId}:`, req.body);

    const userData = await db
      .collection("users")
      .findOne({ id: userId })
      .catch((err) => {
        console.error("MongoDB query failed:", err.message);
        throw err;
      });
    console.log(`User data for userId ${userId}:`, userData);

    if (!userData) {
      console.log(`User not found: userId=${userId}`);
      return res.status(404).json({ error: "User not found" });
    }

    const update = req.body;
    let message, chat, text;

    if (update.message) {
      message = update.message;
      chat = message.chat || {};
      text = message.text || "";
      console.log("Processing regular message:", {
        chatId: chat.id,
        chatType: chat.type,
        text,
      });
    } else if (update.channel_post) {
      message = update.channel_post;
      chat = message.chat || {};
      text = message.text || "";
      console.log("Processing channel post:", {
        chatId: chat.id,
        chatType: chat.type,
        text,
      });
    } else {
      console.log("No message or channel_post found in update");
      return res.json({ status: "ok" });
    }

    const telegramService = new TelegramService(userData.botToken);

    if (userData.alertType === "channel") {
      if (text.startsWith("auth ") && text.length > 5) {
        const receivedCode = text.substring(5).trim();
        const storedCode = userData.authCommand.startsWith("auth ")
          ? userData.authCommand.substring(5).trim()
          : userData.authCommand;

        console.log(
          `Channel auth check: received '${receivedCode}' vs stored '${storedCode}'`
        );

        if (receivedCode === storedCode) {
          console.log(`Channel auth successful for user ${userId}`);
          await db
            .collection("users")
            .updateOne({ id: userId }, { $set: { chatId: String(chat.id) } });
          console.log(`Chat ID ${chat.id} linked to user ID ${userId}`);
          const confirmationMsg = `✅ Authentication successful!\n\nYour ${userData.alertType} is now configured to receive TradingView alerts.`;
          await telegramService.sendMessage(chat.id, confirmationMsg);
          console.log(`Confirmation sent to chat ${chat.id}`);
        } else {
          console.log(`Channel auth failed: codes don't match`);
          await telegramService.sendMessage(
            chat.id,
            "❌ Authentication failed. Please use the correct auth code from the dashboard."
          );
        }
      }
    } else {
      if (
        text.startsWith(`/auth@${userData.botUsername}`) ||
        text.startsWith(`/auth`)
      ) {
        console.log(`Received auth command from chat ${chat.id}`);

        if (
          text.startsWith(`/auth`) &&
          !text.includes(`@${userData.botUsername}`)
        ) {
          await telegramService.sendMessage(
            chat.id,
            `Please use the full command: /auth@${userData.botUsername} <encodedData>`
          );
          return res.json({ status: "ok" });
        }

        try {
          const parts = text.trim().split(" ");
          if (parts.length < 2) {
            throw new Error("Missing encoded ID in auth command");
          }

          const encodedData = parts[1];
          const secret =
            process.env.HMAC_SECRET || "3HKlcLqdkJmvjhoAf8FnYzr4Ua6QBWtG";
          const hmac = crypto.createHmac("sha256", secret);
          hmac.update(`${userId}`);
          const expectedEncodedData = hmac.digest("base64");

          if (encodedData !== expectedEncodedData) {
            throw new Error("Invalid HMAC signature");
          }

          const chatId = chat.id;
          await db
            .collection("users")
            .updateOne({ id: userId }, { $set: { chatId: String(chatId) } });
          console.log(`Chat ID ${chatId} linked to user ID ${userId}`);

          const confirmationMsg = `✅ Authentication successful!\n\nYour ${userData.alertType} is now configured to receive TradingView alerts.`;
          await telegramService.sendMessage(chatId, confirmationMsg);
          console.log(`Confirmation sent to chat ${chatId}`);
        } catch (err) {
          console.error(`Auth command failed: ${err.message}`);
          await telegramService.sendMessage(
            chat.id,
            "❌ Authentication failed. Please ensure you are using the correct command from the dashboard."
          );
        }
      }
    }

    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Error in telegram webhook:", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/api/regenerate/:userId", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const userData = await db.collection("users").findOne({ id: userId });

    if (!userData) {
      flashMessage(req, "User not found", "error");
      return res.status(404).json({ error: "User not found" });
    }

    const newSecretKey = uuidv4();
    await db
      .collection("users")
      .updateOne({ id: userId }, { $set: { secretKey: newSecretKey } });

    flashMessage(req, "Secret key regenerated successfully!", "success");
    res.json({ status: "success" });
  } catch (error) {
    console.error("Error in regenerate:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.use((req, res) => {
  console.log(`404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json({ error: "Not found" });
});

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
