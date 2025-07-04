const express = require("express");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const cors = require("cors"); // Added CORS package

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware to handle plain text, JSON, and CORS
app.use(
  cors({
    origin: "https://xatc.vercel.app", // Allow only your React app
    credentials: true, // Allow headers like X-Session-ID
    methods: ["GET", "POST", "OPTIONS"], // Allow these methods
    allowedHeaders: ["Content-Type", "X-Session-ID"], // Allow these headers
  })
);
app.use(express.text({ type: "text/plain" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Session middleware (simple in-memory session)
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

// In-memory storage (replaces database)
const users = new Map(); // user_id -> user_data
const alerts = []; // list of alert records

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
      if (response.status === 200 && response.data.ok) {
        return response.data.result;
      }
      return null;
    } catch (error) {
      console.error("Error verifying bot token:", error.message);
      return null;
    }
  }

  async sendMessage(chatId, text, parseMode = null) {
    try {
      const payload = {
        chat_id: chatId,
        text: text,
      };
      if (parseMode) payload.parse_mode = parseMode;
      const response = await axios.post(
        `${this.baseUrl}/sendMessage`,
        payload,
        {
          timeout: 10000,
        }
      );
      console.log(`Sent message to chat ${chatId}:`, text);
      return response.status === 200;
    } catch (error) {
      console.error("Error sending message:", error.message);
      return false;
    }
  }

  async setWebhook(webhookUrl) {
    try {
      const payload = { url: webhookUrl };
      const response = await axios.post(`${this.baseUrl}/setWebhook`, payload, {
        timeout: 10000,
      });
      console.log(`Webhook set successfully: ${webhookUrl}`);
      return response.status === 200;
    } catch (error) {
      console.error("Error setting webhook:", error.message);
      return false;
    }
  }

  formatTradingViewAlert(alertData) {
    try {
      console.log("formatTradingViewAlert input:", alertData);
      console.log("Input type:", typeof alertData);
      // Return plain text as-is, or convert non-string to string
      const message =
        typeof alertData === "string" ? alertData : JSON.stringify(alertData);
      console.log("Formatted message:", message);
      return message.trim();
    } catch (error) {
      console.error("Error processing alert:", error.message);
      return `TradingView Alert: ${JSON.stringify(alertData)}`;
    }
  }
}

function generateAuthCommand(botUsername, XAlgoID) {
  const secret = "3HKlcLqdkJmvjhoAf8FnYzr4Ua6QBWtG";
  const data = `${XAlgoID}`; // Use XAlgoID in HMAC source
  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(data);
  const encodedData = hmac.digest("base64");

  console.log(`@${botUsername}: /auth@${botUsername} ${encodedData}`);

  return `/auth@${botUsername} ${encodedData}`;
}

function flashMessage(req, message, type = "success") {
  if (!req.session.flash) {
    req.session.flash = [];
  }
  req.session.flash.push({ message, type });
}

function getFlashMessages(req) {
  const messages = req.session.flash || [];
  req.session.flash = [];
  return messages;
}

// Routes
app.get("/", (req, res) => {
  const flashMessages = getFlashMessages(req);
  res.json({ flashMessages });
});

app.post("/setup", async (req, res) => {
  try {
    const { bot_token, alert_type } = req.body;

    if (!bot_token || !bot_token.trim()) {
      flashMessage(req, "Bot token is required", "error");
      return res.status(400).json({ error: "Bot token is required" });
    }

    // Verify bot token
    const telegramService = new TelegramService(bot_token.trim());
    const botInfo = await telegramService.verifyBotToken();

    if (!botInfo) {
      flashMessage(
        req,
        "Invalid bot token. Please check your token and try again.",
        "error"
      );
      return res.status(400).json({
        error: "Invalid bot token. Please check your token and try again.",
      });
    }

    // Generate user ID and secret
    const userId = users.size + 1;
    const secretKey = uuidv4();
    const botUsername = botInfo.username || "unknown";
    const XAlgoID = "FAOZ135";

    // Generate authentication command
    const authCommand = generateAuthCommand(botUsername, XAlgoID);

    // Store user data in memory
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
    users.set(userId, userData);

    // Set webhook for Telegram bot
    const protocol = req.get("X-Forwarded-Proto") || req.protocol;
    const host = req.get("Host");
    const webhookUrl = `${protocol}://${host}/webhook/telegram/${userId}`;
    await telegramService.setWebhook(webhookUrl);

    flashMessage(req, "Bot configured successfully!", "success");
    res.json({ userId, flashMessages: getFlashMessages(req) });
  } catch (error) {
    console.error("Error in setup:", error.message);
    flashMessage(req, "An error occurred while setting up the bot", "error");
    res.status(500).json({
      error: "An error occurred while setting up the bot",
      flashMessages: getFlashMessages(req),
    });
  }
});

app.get("/dashboard/:userId", (req, res) => {
  const userId = parseInt(req.params.userId);
  const userData = users.get(userId);

  if (!userData) {
    return res.status(404).json({ error: "User not found" });
  }

  // Get recent alerts for this user
  const userAlerts = alerts
    .filter((alert) => alert.userId === userId)
    .slice(-10)
    .reverse();

  // Generate webhook URL
  const protocol = req.get("X-Forwarded-Proto") || req.protocol;
  const host = req.get("Host");
  const webhookUrl = `${protocol}://${host}/webhook/tradingview/${userId}/${userData.secretKey}`;

  // Generate auth status
  let authStatus = {};
  if (userData.alertType === "personal" && !userData.chatId) {
    authStatus = {
      type: "warning",
      message: `To complete personal message setup: <ol><li>Start a chat with your bot <strong>@${userData.botUsername}</strong></li><li>Send this command: <code>${userData.authCommand}</code></li></ol>`,
    };
  } else if (userData.chatId) {
    authStatus = {
      type: "success",
      message: `Your ${userData.alertType} is ready to receive alerts.`,
    };
  } else {
    authStatus = {
      type: "info",
      message: `For ${userData.alertType} alerts: <ol><li>Add your bot <strong>@${userData.botUsername}</strong> to your ${userData.alertType}</li><li>Send this command: <code>${userData.authCommand}</code></li></ol>`,
    };
  }

  res.json({
    botUsername: userData.botUsername,
    authStatus,
    webhookUrl,
    userId,
    recentAlerts: userAlerts,
    flashMessages: getFlashMessages(req),
  });
});

app.post("/webhook/tradingview/:userId/:secretKey", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const secretKey = req.params.secretKey;
    const userData = users.get(userId);

    if (!userData || userData.secretKey !== secretKey) {
      console.log(
        `Unauthorized access: userId=${userId}, secretKey=${secretKey}`
      );
      return res.status(401).json({ error: "Unauthorized" });
    }

    // Log full request details for debugging
    console.log("Webhook request headers:", req.headers);
    console.log("Webhook request body:", req.body);
    console.log("Content-Type:", req.get("Content-Type"));

    // Get webhook data, handle plain text or JSON
    const webhookData =
      typeof req.body === "string" ? req.body : JSON.stringify(req.body);
    console.log(`Received TradingView alert for user ${userId}:`, webhookData);

    // Check if chat is configured
    if (!userData.chatId) {
      const errorMsg =
        "Chat not configured. Please complete authentication first.";
      console.log(`Error: ${errorMsg}`);
      alerts.push({
        userId,
        webhookData,
        sentSuccessfully: false,
        createdAt: new Date(),
        errorMessage: errorMsg,
      });
      return res.status(400).json({ error: errorMsg });
    }

    // Send alert to Telegram
    const telegramService = new TelegramService(userData.botToken);
    const formattedMessage =
      telegramService.formatTradingViewAlert(webhookData);
    console.log(
      `Sending to Telegram chat ${userData.chatId}:`,
      formattedMessage
    );

    const success = await telegramService.sendMessage(
      userData.chatId,
      formattedMessage
    );

    // Log alert
    alerts.push({
      userId,
      webhookData,
      sentSuccessfully: success,
      createdAt: new Date(),
      errorMessage: success ? null : "Failed to send message",
    });

    if (success) {
      console.log(`Alert sent successfully to chat ${userData.chatId}`);
      return res.json({ status: "success" });
    } else {
      console.error(`Failed to send alert to chat ${userData.chatId}`);
      return res.status(500).json({ error: "Failed to send alert" });
    }
  } catch (error) {
    console.error("Error in tradingview webhook:", error.message);
    alerts.push({
      userId: parseInt(req.params.userId),
      webhookData:
        typeof req.body === "string" ? req.body : JSON.stringify(req.body),
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
    const userData = users.get(userId);

    if (!userData) {
      console.log(`User not found: userId=${userId}`);
      return res.status(404).json({ error: "User not found" });
    }

    const update = req.body;
    console.log("Received Telegram update:", JSON.stringify(update));

    // Handle message updates
    if (update.message) {
      const message = update.message;
      const chat = message.chat || {};
      const text = message.text || "";

      // Check for auth command
      if (text.startsWith(`/auth@${userData.botUsername}`)) {
        const chatId = chat.id;
        const chatType = chat.type || "private";

        console.log(
          `Received auth command from chat ${chatId}, type: ${chatType}`
        );

        // Update user's chat_id
        userData.chatId = String(chatId);
        users.set(userId, userData);

        // Send confirmation
        const telegramService = new TelegramService(userData.botToken);
        const confirmationMsg = `✅ Authentication successful!\n\nYour ${userData.alertType} is now configured to receive TradingView alerts.`;
        await telegramService.sendMessage(chatId, confirmationMsg);

        console.log(`Chat ${chatId} configured for user ${userId}`);
      }
    }

    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Error in telegram webhook:", error.message);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/regenerate/:userId", (req, res) => {
  const userId = parseInt(req.params.userId);
  const userData = users.get(userId);

  if (!userData) {
    flashMessage(req, "User not found", "error");
    return res.status(404).json({
      error: "User not found",
      flashMessages: getFlashMessages(req),
    });
  }

  // Generate new secret
  userData.secretKey = uuidv4();
  users.set(userId, userData);

  flashMessage(req, "Secret key regenerated successfully!", "success");
  res.json({
    userId,
    flashMessages: getFlashMessages(req),
  });
});

// Error handlers
app.use((req, res) => {
  console.log(`404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json({ error: "Page not found" });
});

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);
  res.status(500).json({ error: "Internal server error" });
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
  console.log("🤖 TradingView Telegram Bot - Node.js Version");
  console.log(`📱 Server running on http://localhost:${PORT}`);
  console.log("💡 Press Ctrl+C to stop the server");
});

module.exports = app;
