const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const mongoose = require("mongoose");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");

const TradingViewBotModel = require("./model/TradingViewBotModel");

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
        text: `${text}\n\nPowered by xalgos.in`,
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
      console.error("Error sending message:", error.message);
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
        return "📊 TradingView Alert: No data received\n\nPowered by xalgos.in";
      }

      if (contentType.includes("text/plain") || typeof alertData === "string") {
        return `📊 TradingView Alert\n\n${
          alertData.trim() || "Empty message"
        }\n\nPowered by xalgos.in`;
      }

      if (
        contentType.includes("application/json") ||
        typeof alertData === "object"
      ) {
        try {
          const formatted = JSON.stringify(alertData, null, 2);
          return `📊 TradingView Alert\n\n\`\`\`json\n${formatted}\n\`\`\`\n\nPowered by xalgos.in`;
        } catch (error) {
          console.error("Error formatting JSON:", error.message);
          return `📊 TradingView Alert: Malformed JSON data: ${JSON.stringify(
            alertData
          )}\n\nPowered by xalgos.in`;
        }
      }

      return `📊 TradingView Alert: Unsupported data format: ${String(
        alertData
      )}\n\nPowered by xalgos.in`;
    } catch (error) {
      console.error("Error processing alert:", error.message);
      return `📊 TradingView Alert: Error processing data: ${String(
        alertData
      )}\n\nPowered by xalgos.in`;
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

function setup() {
  const app = express();

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

  // Debug middleware
  app.use((req, res, next) => {
    console.log(`Request received: ${req.method} ${req.url}`);
    next();
  });

  // API Routes
  app.get("/api", (req, res) => {
    const messages = req.session.flash || [];
    req.session.flash = [];
    res.json({ flashMessages: messages });
  });

  app.post("/api/setup", async (req, res) => {
    try {
      const { bot_token, image, XId } = req.body;
      if (!bot_token || !bot_token.trim() || !XId || !XId.trim()) {
        req.session.flash = req.session.flash || [];
        req.session.flash.push({
          message: "Bot token and XId are required\n\nPowered by xalgos.in",
          type: "error",
        });
        return res.status(400).json({
          error: "Bot token and XId are required\n\nPowered by xalgos.in",
        });
      }

      const telegramService = new TelegramService(bot_token.trim());
      const botInfo = await telegramService.verifyBotToken();
      if (!botInfo) {
        req.session.flash = req.session.flash || [];
        req.session.flash.push({
          message:
            "Invalid bot token. Please check your token and try again.\n\nPowered by xalgos.in",
          type: "error",
        });
        return res
          .status(400)
          .json({ error: "Invalid bot token\n\nPowered by xalgos.in" });
      }

      let userId;
      let existingUser;
      let attempts = 0;
      const maxAttempts = 10;

      do {
        const userCount = await TradingViewBotModel.countDocuments();
        userId = userCount + 1;
        existingUser = await TradingViewBotModel.findOne({
          id: userId,
          XalgoID: XId,
        });
        attempts++;
        if (attempts > maxAttempts) {
          req.session.flash = req.session.flash || [];
          req.session.flash.push({
            message:
              "Unable to assign a unique user ID.\n\nPowered by xalgos.in",
            type: "error",
          });
          return res.status(500).json({
            error: "Unable to assign a unique user ID\n\nPowered by xalgos.in",
          });
        }
      } while (existingUser);

      const secretKey = uuidv4();
      const botUsername = botInfo.username || "unknown";
      const alertTypes = ["personal", "group", "channel"];
      const alerts = alertTypes.map((alertType) => ({
        alertType,
        authCommand: generateAuthCommand(botUsername, userId, alertType),
      }));

      const protocol = req.get("X-Forwarded-Proto") || req.protocol;
      const host = req.get("Host");
      const webhookUrl = `${protocol}://${host}/webhook/telegram/${userId}`;

      const userData = {
        id: userId,
        botToken: bot_token.trim(),
        botUsername,
        image: image || null,
        secretKey,
        chatId: null,
        alerts,
        XalgoID: XId,
        webhookURL: webhookUrl,
        createdAt: new Date(),
      };

      console.log("Inserting user:", JSON.stringify(userData, null, 2));
      const newUser = new TradingViewBotModel(userData);
      await newUser.save();
      await telegramService.setWebhook(webhookUrl);

      const userAlerts = await TradingViewBotModel.find({
        id: userId,
      })
        .sort({ createdAt: -1 })
        .limit(10);
      const webhookTradingViewUrl = `${protocol}://${host}/webhook/tradingview/${userId}/${secretKey}`;

      const routes = [
        {
          path: `/webhook/tradingview/${userId}/${secretKey}`,
          method: "post",
          handler: async (req, res) => {
            try {
              const userId = parseInt(req.params.userId);
              const secretKey = req.params.secretKey;
              const userData = await TradingViewBotModel.findOne({
                id: userId,
              });

              if (!userData || userData.secretKey !== secretKey) {
                console.log(
                  `Unauthorized access: userId=${userId}, secretKey=${secretKey}`
                );
                return res
                  .status(401)
                  .json({ error: "Unauthorized\n\nPowered by xalgos.in" });
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

              if (!userData.chatId) {
                const errorMsg =
                  "Chat not configured. Please complete authentication first.";
                await TradingViewBotModel.updateOne(
                  { id: userId },
                  {
                    $push: {
                      alerts: {
                        webhookData,
                        contentType,
                        sentSuccessfully: false,
                        createdAt: new Date(),
                        errorMessage: errorMsg,
                      },
                    },
                  }
                );
                return res.status(400).json({
                  error:
                    "Chat not configured. Please complete authentication first.\n\nPowered by xalgos.in",
                });
              }

              const telegramService = new TelegramService(userData.botToken);
              const formattedMessage = telegramService.formatTradingViewAlert(
                webhookData,
                contentType
              );
              const success = await telegramService.sendMessage(
                userData.chatId,
                formattedMessage,
                contentType.includes("json") ? "Markdown" : null
              );

              await TradingViewBotModel.updateOne(
                { id: userId },
                {
                  $push: {
                    alerts: {
                      webhookData,
                      contentType,
                      formattedMessage,
                      sentSuccessfully: success,
                      createdAt: new Date(),
                      errorMessage: success ? null : "Failed to send message",
                    },
                  },
                }
              );

              return success
                ? res.json({ status: "success" })
                : res.status(500).json({
                    error: "Failed to send alert\n\nPowered by xalgos.in",
                  });
            } catch (error) {
              console.error(
                "Error in tradingview webhook:",
                error.message,
                error.stack
              );
              await TradingViewBotModel.updateOne(
                { id: parseInt(req.params.userId) },
                {
                  $push: {
                    alerts: {
                      webhookData: req.body || String(req.rawBody || ""),
                      contentType: req.headers["content-type"] || "unknown",
                      sentSuccessfully: false,
                      createdAt: new Date(),
                      errorMessage: error.message,
                    },
                  },
                }
              );
              return res.status(500).json({
                error: "Internal server error\n\nPowered by xalgos.in",
              });
            }
          },
        },
        {
          path: `/webhook/telegram/${userId}`,
          method: "post",
          handler: async (req, res) => {
            try {
              const userId = parseInt(req.params.userId);
              console.log(
                `Received Telegram update for userId ${userId}:`,
                JSON.stringify(req.body, null, 2)
              );

              const userData = await TradingViewBotModel.findOne({
                id: userId,
              });
              if (!userData) {
                console.log(`User not found: userId=${userId}`);
                return res
                  .status(404)
                  .json({ error: "User not found\n\nPowered by xalgos.in" });
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
                    await TradingViewBotModel.updateOne(
                      { id: userId },
                      { $set: { chatId: String(chat.id) } }
                    );
                    console.log(
                      `Channel auth successful: chatId ${chat.id} linked to userId ${userId}`
                    );
                    await telegramService.sendMessage(
                      chat.id,
                      `✅ Authentication successful!\nYour ${alert.alertType} is now configured to receive TradingView alerts.`
                    );
                  } else {
                    console.log(`Channel auth failed: codes don't match`);
                    await telegramService.sendMessage(
                      chat.id,
                      `❌ Authentication failed. Please use the correct auth code from the dashboard.`
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
                      `Please use the full command: /auth@${userData.botUsername} <encodedData>`
                    );
                    return res.json({ status: "ok" });
                  }

                  const parts = text.trim().split(" ");
                  if (parts.length < 2) {
                    console.log(`Invalid auth command: missing encoded data`);
                    await telegramService.sendMessage(
                      chat.id,
                      `❌ Authentication failed. Please ensure you are using the correct command from the dashboard.`
                    );
                    return res.json({ status: "ok" });
                  }

                  const encodedData = parts[1];
                  const secret =
                    process.env.HMAC_SECRET ||
                    "3HKlcLqdkJmvjhoAf8FnYzr4Ua6QBWtG";
                  const hmac = crypto.createHmac("sha256", secret);
                  hmac.update(`${userId}`);
                  const expectedEncodedData = hmac.digest("base64");

                  if (encodedData === expectedEncodedData) {
                    await TradingViewBotModel.updateOne(
                      { id: userId },
                      { $set: { chatId: String(chat.id) } }
                    );
                    console.log(
                      `Auth successful: chatId ${chat.id} linked to userId ${userId}`
                    );
                    await telegramService.sendMessage(
                      chat.id,
                      `✅ Authentication successful!\nYour ${alert.alertType} is now configured to receive TradingView alerts.`
                    );
                  } else {
                    console.log(`Auth failed: invalid HMAC signature`);
                    await telegramService.sendMessage(
                      chat.id,
                      `❌ Authentication failed. Please ensure you are using the correct command from the dashboard.`
                    );
                  }
                }
              }

              return res.json({ status: "ok" });
            } catch (error) {
              console.error(
                "Error in telegram webhook:",
                error.message,
                error.stack
              );
              return res.status(500).json({
                error: "Internal server error\n\nPowered by xalgos.in",
              });
            }
          },
        },
      ];

      req.session.flash = req.session.flash || [];
      req.session.flash.push({
        message: "Bot configured successfully!\n\nPowered by xalgos.in",
        type: "success",
      });
      return res.json({
        redirect: `/dashboard/${userId}`,
        flashMessages: req.session.flash,
        userData: newUser,
        recentAlerts: userAlerts,
        webhookUrl: webhookTradingViewUrl,
        routes,
      });
    } catch (error) {
      console.error("Error in setup:", error.message, error.stack);
      req.session.flash = req.session.flash || [];
      req.session.flash.push({
        message:
          "An error occurred while setting up the bot\n\nPowered by xalgos.in",
        type: "error",
      });
      return res
        .status(500)
        .json({ error: "Internal server error\n\nPowered by xalgos.in" });
    }
  });

  app.get("/api/dashboard/:userId", async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      const userData = await TradingViewBotModel.findOne({ id: userId });

      if (!userData) {
        req.session.flash = req.session.flash || [];
        req.session.flash.push({
          message: "User not found\n\nPowered by xalgos.in",
          type: "error",
        });
        return res
          .status(404)
          .json({ error: "User not found\n\nPowered by xalgos.in" });
      }

      const userAlerts = await TradingViewBotModel.find({ id: userId })
        .sort({ createdAt: -1 })
        .limit(10);
      const protocol = req.get("X-Forwarded-Proto") || req.protocol;
      const host = req.get("Host");
      const webhookUrl = `${protocol}://${host}/webhook/tradingview/${userId}/${userData.secretKey}`;

      res.json({
        flashMessages: req.session.flash || [],
        userData,
        recentAlerts: userAlerts,
        webhookUrl,
      });
      req.session.flash = [];
    } catch (error) {
      console.error("Error in dashboard:", error.message, error.stack);
      req.session.flash = req.session.flash || [];
      req.session.flash.push({
        message:
          "An error occurred while fetching dashboard data\n\nPowered by xalgos.in",
        type: "error",
      });
      res
        .status(500)
        .json({ error: "Internal server error\n\nPowered by xalgos.in" });
    }
  });

  app.get("/api/regenerate/:userId", async (req, res) => {
    try {
      const userId = parseInt(req.params.userId);
      const userData = await TradingViewBotModel.findOne({ id: userId });

      if (!userData) {
        req.session.flash = req.session.flash || [];
        req.session.flash.push({
          message: "User not found\n\nPowered by xalgos.in",
          type: "error",
        });
        return res
          .status(404)
          .json({ error: "User not found\n\nPowered by xalgos.in" });
      }

      const newSecretKey = uuidv4();
      await TradingViewBotModel.updateOne(
        { id: userId },
        { $set: { secretKey: newSecretKey } }
      );

      req.session.flash = req.session.flash || [];
      req.session.flash.push({
        message: "Secret key regenerated successfully!\n\nPowered by xalgos.in",
        type: "success",
      });
      res.json({ status: "success", newSecretKey });
    } catch (error) {
      console.error("Error in regenerate:", error.message, error.stack);
      req.session.flash = req.session.flash || [];
      req.session.flash.push({
        message:
          "An error occurred while regenerating secret key\n\nPowered by xalgos.in",
        type: "error",
      });
      res
        .status(500)
        .json({ error: "Internal server error\n\nPowered by xalgos.in" });
    }
  });

  app.use((req, res) => {
    console.log(`404 Not Found: ${req.method} ${req.url}`);
    res.status(404).json({ error: "Not found\n\nPowered by xalgos.in" });
  });

  app.use((error, req, res, next) => {
    console.error("Server error:", error.message, error.stack);
    res
      .status(500)
      .json({ error: "Internal server error\n\nPowered by xalgos.in" });
  });

  return app;
}

module.exports = { setup };
