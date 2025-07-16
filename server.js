const express = require("express");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
const cors = require("cors");
const { MongoClient } = require("mongodb");

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
      const payload = {
        chat_id: chatId,
        text: `${text}\n*__Powered by xalgos.in__*`,
      };
      if (parseMode) payload.parse_mode = parseMode;
      const response = await axios.post(
        `${this.baseUrl}/sendMessage`,
        payload,
        { timeout: 10000 }
      );
      console.log(`Sent message to chat ${chatId}:`, text);
      return response.status === 200;
    } catch (error) {
      console.error("Error sending message to chat ${chatId}:", error.message);
      return false;
    }
  }

  async setWebhook(webhookUrl) {
    try {
      const response = await axios.post(
        `${this.baseUrl}/setWebhook`,
        { url: webhookUrl, allowed_updates: ["message", "channel_post"] },
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
        return "No data received";
      }

      if (contentType.includes("text/plain") || typeof alertData === "string") {
        return `${alertData.trim() || "Empty message"}`;
      }

      if (
        contentType.includes("application/json") ||
        typeof alertData === "object"
      ) {
        try {
          const formatted = JSON.stringify(alertData, null, 2);
          return `\`\`\`json\n${formatted}\n\`\`\``;
        } catch (error) {
          console.error("Error formatting JSON:", error.message);
          return `Malformed JSON data: ${JSON.stringify(alertData)}`;
        }
      }

      return `Unsupported data format: ${String(alertData)}`;
    } catch (error) {
      console.error("Error processing alert:", error.message);
      return `Error processing data: ${String(alertData)}`;
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
  req.session.flash.push({
    message: message,
    type,
  });
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
    const { bot_token, image, XId } = req.body;

    if (!bot_token || !bot_token.trim()) {
      flashMessage(req, "Bot token is required", "error");
      return res.status(400).json({
        error: "Bot token is required",
      });
    }

    const existingUser = await db
      .collection("users")
      .findOne({ botToken: bot_token.trim() });
    if (existingUser) {
      flashMessage(req, "This bot token is already registered", "error");
      return res.status(400).json({
        error: "This bot token is already registered",
      });
    }

    const telegramService = new TelegramService(bot_token.trim());
    const botInfo = await telegramService.verifyBotToken();

    if (!botInfo) {
      flashMessage(
        req,
        "Invalid bot token. Please check your token and try again.",
        "error"
      );
      return res.status(400).json({
        error: "Invalid bot token",
      });
    }

    const userCount = await db.collection("users").countDocuments();
    const userId = userCount + 1;

    const secretKey = uuidv4();
    const botUsername = botInfo.username || "unknown";
    const alertTypes = ["personal", "group", "channel"];
    const alerts = alertTypes.map((alertType) => ({
      alertType,
      authCommand: generateAuthCommand(botUsername, userId, alertType),
      chatId: null,
    }));

    const protocol = req.get("X-Forwarded-Proto") || req.protocol;
    const host = req.get("Host");
    const webhookUrl = `${protocol}://${host}/webhook/telegram/${userId}`;
    const webhookTradingViewUrl = `${protocol}://${host}/webhook/tradingview/${userId}/${secretKey}`;

    const userData = {
      id: userId,
      botToken: bot_token.trim(),
      botUsername,
      image: image || null,
      secretKey,
      alerts,
      XalgoID: XId || null,
      webhookURL: webhookTradingViewUrl,
      createdAt: new Date(),
    };

    console.log("Inserting user:", JSON.stringify(userData, null, 2));
    await db.collection("users").insertOne(userData);
    await telegramService.setWebhook(webhookUrl);

    const userAlerts = await db
      .collection("alerts")
      .find({ userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .toArray();

    flashMessage(req, "Bot configured successfully!", "success");
    return res.json({
      redirect: `/dashboard/${userId}`,
      flashMessages: getFlashMessages(req),
      userData,
      recentAlerts: userAlerts,
      webhookUrl: webhookTradingViewUrl,
    });
  } catch (error) {
    console.error("Error in setup:", error.message, error.stack);
    flashMessage(req, "An error occurred while setting up the bot", "error");
    return res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.get("/api/dashboard/:userId", async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const userData = await db.collection("users").findOne({ id: userId });

    if (!userData) {
      flashMessage(req, "User not found", "error");
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
    console.error("Error in dashboard:", error.message, error.stack);
    flashMessage(
      req,
      "An error occurred while fetching dashboard data",
      "error"
    );
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

    const contentType = req.headers["content-type"] || "unknown";
    console.log(
      `Received TradingView alert for user ${userId}, Content-Type: ${contentType}, Data:`,
      JSON.stringify(req.body, null, 2)
    );

    let webhookData;
    if (contentType.includes("application/json")) {
      webhookData = req.body;
    } else if (contentType.includes("text/plain")) {
      webhookData = req.body;
    } else {
      webhookData = req.body || String(req.rawBody || "");
      console.warn(
        `Unsupported Content-Type: ${contentType}, treating as raw data`
      );
    }

    const telegramService = new TelegramService(userData.botToken);
    const formattedMessage = telegramService.formatTradingViewAlert(
      webhookData,
      contentType
    );

    let allSuccess = true;
    const alertResults = [];

    // Send message to all authenticated chatIds in alerts array
    for (const alert of userData.alerts) {
      if (alert.chatId) {
        const success = await telegramService.sendMessage(
          alert.chatId,
          formattedMessage,
          contentType.includes("json") ? "Markdown" : null
        );
        alertResults.push({
          alertType: alert.alertType,
          chatId: alert.chatId,
          sentSuccessfully: success,
          errorMessage: success
            ? null
            : `Failed to send message to ${alert.alertType}`,
        });
        if (!success) allSuccess = false;
      }
    }

    if (alertResults.length === 0) {
      const errorMsg =
        "No chats configured. Please complete authentication for at least one alert type.";
      await db.collection("alerts").insertOne({
        userId,
        webhookData,
        contentType,
        sentSuccessfully: false,
        createdAt: new Date(),
        errorMessage: errorMsg,
      });
      return res.status(400).json({
        error: "No chats configured. Please complete authentication first.",
      });
    }

    // Store alert in the database
    await db.collection("alerts").insertOne({
      userId,
      webhookData,
      contentType,
      formattedMessage,
      sentSuccessfully: allSuccess,
      createdAt: new Date(),
      errorMessage: allSuccess ? null : "Failed to send to some chats",
      alertResults,
    });

    return allSuccess
      ? res.json({ status: "success" })
      : res.status(500).json({ error: "Failed to send alert to some chats" });
  } catch (error) {
    console.error("Error in tradingview webhook:", error.message, error.stack);
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
    console.log(
      `Received Telegram update for userId ${userId}:`,
      JSON.stringify(req.body, null, 2)
    );

    const userData = await db.collection("users").findOne({ id: userId });
    if (!userData) {
      console.log(`User not found: userId=${userId}`);
      return res.status(404).json({ error: "User not found" });
    }

    const telegramService = new TelegramService(userData.botToken);
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
      console.log(
        "No message or channel_post found in update:",
        JSON.stringify(update, null, 2)
      );
      return res.json({ status: "ok" });
    }

    for (const alert of userData.alerts) {
      if (
        alert.alertType === "channel" &&
        text.startsWith("auth ") &&
        text.length > 5
      ) {
        const receivedCode = text.substring(5).trim();
        const storedCode = alert.authCommand.startsWith("auth ")
          ? alert.authCommand.substring(5).trim()
          : alert.authCommand;

        console.log(
          `Channel auth check: received '${receivedCode}' vs stored '${storedCode}'`
        );

        if (receivedCode === storedCode) {
          await db
            .collection("users")
            .updateOne(
              { id: userId, "alerts.alertType": alert.alertType },
              { $set: { "alerts.$.chatId": String(chat.id) } }
            );
          console.log(
            `Channel auth successful: chatId ${chat.id} linked to userId ${userId} for ${alert.alertType}`
          );
          await telegramService.sendMessage(
            chat.id,
            `✅ Authentication successful!\nYour ${alert.alertType} is now configured to receive TradingView alerts.`,
            "Markdown"
          );
        } else {
          console.log(`Channel auth failed: codes don't match`);
          await telegramService.sendMessage(
            chat.id,
            `❌ Authentication failed. Please use the correct auth code from the dashboard.`,
            "Markdown"
          );
        }
      } else if (
        (text.startsWith(`/auth@${userData.botUsername}`) ||
          text.startsWith(`/auth`)) &&
        ["personal", "group"].includes(alert.alertType)
      ) {
        if (
          text.startsWith(`/auth`) &&
          !text.includes(`@${userData.botUsername}`)
        ) {
          console.log(`Invalid auth command format: ${text}`);
          await telegramService.sendMessage(
            chat.id,
            `Please use the full command: /auth@${userData.botUsername} <encodedData>`,
            "Markdown"
          );
          return res.json({ status: "ok" });
        }

        const parts = text.trim().split(" ");
        if (parts.length < 2) {
          console.log(`Invalid auth command: missing encoded data`);
          await telegramService.sendMessage(
            chat.id,
            `❌ Authentication failed. Please ensure you are using the correct command from the dashboard.`,
            "Markdown"
          );
          return res.json({ status: "ok" });
        }

        const encodedData = parts[1];
        const secret =
          process.env.HMAC_SECRET || "3HKlcLqdkJmvjhoAf8FnYzr4Ua6QBWtG";
        const hmac = crypto.createHmac("sha256", secret);
        hmac.update(`${userId}`);
        const expectedEncodedData = hmac.digest("base64");

        if (encodedData === expectedEncodedData) {
          await db
            .collection("users")
            .updateOne(
              { id: userId, "alerts.alertType": alert.alertType },
              { $set: { "alerts.$.chatId": String(chat.id) } }
            );
          console.log(
            `Auth successful: chatId ${chat.id} linked to userId ${userId} for ${alert.alertType}`
          );
          await telegramService.sendMessage(
            chat.id,
            `✅ Authentication successful!\nYour ${alert.alertType} is now configured to receive TradingView alerts.`,
            "Markdown"
          );
        } else {
          console.log(`Auth failed: invalid HMAC signature`);
          await telegramService.sendMessage(
            chat.id,
            `❌ Authentication failed. Please ensure you are using the correct command from the dashboard.`,
            "Markdown"
          );
        }
      }
    }

    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Error in telegram webhook:", error.message, error.stack);
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
    res.json({ status: "success", newSecretKey });
  } catch (error) {
    console.error("Error in regenerate:", error.message, error.stack);
    flashMessage(
      req,
      "An error occurred while regenerating secret key",
      "error"
    );
    res.status(500).json({ error: "Internal server error" });
  }
});

app.use((req, res) => {
  console.log(`404 Not Found: ${req.method} ${req.url}`);
  res.status(404).json({ error: "Not found" });
});

app.use((error, req, res, next) => {
  console.error("Server error:", error.message, error.stack);
  res.status(500).json({ error: "Internal server error" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
