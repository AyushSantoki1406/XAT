const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const axios = require("axios");
const { v4: uuidv4 } = require("uuid");
const logger = require("winston");
const base64 = require("base-64");
const cors = require("cors");
const https = require("https");

const app = express();
app.use(express.json());
app.use(express.static("public"));
app.use(
  cors({
    origin: "*", // Allow all origins for development
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);

// Logger setup
logger.configure({
  transports: [
    new logger.transports.Console({
      format: logger.format.combine(
        logger.format.timestamp(),
        logger.format.printf(
          ({ timestamp, level, message }) =>
            `${timestamp} - ${level}: ${message}`
        )
      ),
    }),
  ],
});

// MongoDB setup
const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017";
const DB_NAME = "telegram_tradingview";
let db;

const initDatabase = async () => {
  try {
    const client = new MongoClient(MONGODB_URI, { useUnifiedTopology: true });
    await client.connect();
    db = client.db(DB_NAME);
    logger.info("Connected to MongoDB");

    const collections = await db.listCollections().toArray();
    const collectionNames = collections.map((c) => c.name);

    if (!collectionNames.includes("users")) {
      await db.createCollection("users");
      await db
        .collection("users")
        .createIndex({ telegram_user_id: 1 }, { unique: true });
    }

    if (!collectionNames.includes("alerts")) {
      await db.createCollection("alerts");
    }
  } catch (error) {
    logger.error(`Database connection error: ${error}`);
    throw error;
  }
};

class TelegramService {
  constructor(botToken) {
    this.botToken = botToken;
    this.baseUrl = `https://api.telegram.org/bot${botToken}`;
    this.axiosInstance = axios.create({
      httpsAgent: new https.Agent({
        rejectUnauthorized: false, // Disable certificate verification for development
      }),
      timeout: 30000, // 30 seconds timeout
    });
  }

  async verifyBotToken() {
    const maxRetries = 3;
    let attempt = 1;

    while (attempt <= maxRetries) {
      try {
        console.log(
          `Verifying bot token (attempt ${attempt}): ${this.botToken.substring(
            0,
            10
          )}...`
        );
        const response = await this.axiosInstance.get(`${this.baseUrl}/getMe`);
        const data = response.data;
        if (data.ok) {
          logger.info(`Bot token verified: @${data.result.username}`);
          return {
            valid: true,
            bot_username: data.result.username,
            bot_name: data.result.first_name,
            bot_id: data.result.id,
          };
        }
        logger.error(`Bot token verification failed: ${JSON.stringify(data)}`);
        return { valid: false, error: data.description || "Invalid token" };
      } catch (error) {
        logger.error(
          `Error during bot verification (attempt ${attempt}): ${error.message}`
        );
        if (attempt === maxRetries) {
          return { valid: false, error: error.message };
        }
        attempt++;
        await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
      }
    }
  }

  async sendMessage(chatId, text, parseMode = "HTML") {
    try {
      const response = await this.axiosInstance.post(
        `${this.baseUrl}/sendMessage`,
        {
          chat_id: chatId,
          text,
          parse_mode: parseMode,
        }
      );
      const data = response.data;
      if (data.ok) {
        logger.info(`Message sent successfully to chat ${chatId}`);
        return { success: true, message_id: data.result.message_id };
      }
      logger.error(`Failed to send message: ${JSON.stringify(data)}`);
      return { success: false, error: data.description || "Unknown error" };
    } catch (error) {
      logger.error(`Error sending message: ${error.message}`);
      return { success: false, error: error.message };
    }
  }

  async setWebhook(webhookUrl) {
    const maxRetries = 3;
    let attempt = 1;

    while (attempt <= maxRetries) {
      try {
        console.log(`Setting webhook (attempt ${attempt}): ${webhookUrl}`);
        const response = await this.axiosInstance.post(
          `${this.baseUrl}/setWebhook`,
          {
            url: webhookUrl,
            allowed_updates: ["message"],
          }
        );
        const data = response.data;
        if (data.ok) {
          logger.info(`Webhook set successfully: ${webhookUrl}`);
          return { success: true };
        }
        logger.error(`Failed to set webhook: ${JSON.stringify(data)}`);
        return { success: false, error: data.description || "Unknown error" };
      } catch (error) {
        logger.error(
          `Error setting webhook (attempt ${attempt}): ${
            error.message
          } - ${JSON.stringify(error.response?.data || {})}`
        );
        if (attempt === maxRetries) {
          return { success: false, error: error.message };
        }
        attempt++;
        await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
      }
    }
  }

  formatTradingviewAlert(alertData) {
    try {
      if (typeof alertData === "string") {
        try {
          alertData = JSON.parse(alertData);
        } catch {
          return `📊 <b>TradingView Alert</b>\n\n${alertData}`;
        }
      }
      let message = "📊 <b>TradingView Alert</b>\n\n";
      if (typeof alertData === "object" && alertData !== null) {
        for (const [key, value] of Object.entries(alertData)) {
          const formattedKey = key
            .replace("_", " ")
            .replace(/\b\w/g, (c) => c.toUpperCase());
          message += `<b>${formattedKey}:</b> ${value}\n`;
        }
      } else {
        message += String(alertData);
      }
      message += `\n⏰ <i>Alert received at ${new Date()
        .toISOString()
        .replace("T", " ")
        .slice(0, 19)}</i>`;
      return message;
    } catch (error) {
      logger.error(`Error formatting alert: ${error}`);
      return `📊 <b>TradingView Alert</b>\n\n${String(alertData)}`;
    }
  }
}

const generateAuthCommand = (botUsername, userId) => {
  const uniqueData = `${userId}:${Math.floor(Date.now() / 1000)}`;
  const encodedData = base64.encode(uniqueData);
  return `/auth@${botUsername} ${encodedData}`;
};

// API Routes
app.post("/api/setup_bot", async (req, res) => {
  console.log("Received POST /api/setup_bot:", req.body);
  const { bot_token, alert_type = "personal" } = req.body;
  if (!bot_token) {
    return res.status(400).json({ error: "Bot token is required" });
  }

  const telegramService = new TelegramService(bot_token);
  const verificationResult = await telegramService.verifyBotToken();

  if (!verificationResult.valid) {
    return res.status(400).json({ error: verificationResult.error });
  }

  const { bot_username, bot_id } = verificationResult;

  try {
    let user = await db
      .collection("users")
      .findOne({ telegram_user_id: bot_id.toString() });
    let userId;

    if (user) {
      userId = user._id.toString();
      const newAuthCommand = generateAuthCommand(bot_username, userId);
      await db.collection("users").updateOne(
        { telegram_user_id: bot_id.toString() },
        {
          $set: {
            bot_token,
            bot_username,
            alert_type,
            auth_command: newAuthCommand,
            chat_id: null,
          },
        }
      );
    } else {
      const secretKey = uuidv4();
      const tempAuthCommand = `/auth@${bot_username} temp`;
      const result = await db.collection("users").insertOne({
        telegram_user_id: bot_id.toString(),
        bot_token,
        bot_username,
        secret_key: secretKey,
        auth_command: tempAuthCommand,
        alert_type,
        created_at: new Date(),
      });
      userId = result.insertedId.toString();
      const finalAuthCommand = generateAuthCommand(bot_username, userId);
      await db
        .collection("users")
        .updateOne(
          { _id: new ObjectId(userId) },
          { $set: { auth_command: finalAuthCommand } }
        );
      user = await db
        .collection("users")
        .findOne({ _id: new ObjectId(userId) });
    }

    // Use Render URL for webhook
    const webhookBaseUrl = "https://xat-fg8p.onrender.com";
    const webhookUrl = `${webhookBaseUrl}/api/webhook/telegram/${userId}`;
    const webhookResult = await telegramService.setWebhook(webhookUrl);
    if (!webhookResult.success) {
      logger.error(
        `Webhook setup failed for ${webhookUrl}: ${webhookResult.error}`
      );
      return res.status(500).json({
        error: `Bot verified but webhook setup failed: ${webhookResult.error}`,
      });
    }

    res.json({ user_id: userId, bot_username });
  } catch (error) {
    logger.error(`Error setting up bot: ${error}`);
    res.status(500).json({ error: "Bot verified but setup failed" });
  }
});

app.get("/api/dashboard/:userId", async (req, res) => {
  console.log("Received GET /api/dashboard/:userId:", req.params.userId);
  const { userId } = req.params;
  try {
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const alerts = await db
      .collection("alerts")
      .find({ user_id: userId })
      .sort({ created_at: -1 })
      .limit(5)
      .toArray();

    const webhookBaseUrl = "https://xat-fg8p.onrender.com";
    const webhookUrl = `${webhookBaseUrl}/api/webhook/tradingview/${userId}/${user.secret_key}`;
    res.json({ user, webhook_url: webhookUrl, alerts });
  } catch (error) {
    logger.error(`Error loading dashboard: ${error}`);
    res.status(404).json({ error: "User not found" });
  }
});

app.post("/api/webhook/tradingview/:userId/:secretKey", async (req, res) => {
  console.log(
    "Received POST /api/webhook/tradingview/:userId/:secretKey:",
    req.params
  );
  const { userId, secretKey } = req.params;
  try {
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(userId), secret_key: secretKey });
    if (!user) {
      logger.warning(`Invalid user_id or secret key: ${userId}`);
      return res.status(403).json({ error: "Invalid user or secret key" });
    }

    const alertData = req.is("json") ? req.body : req.body.toString();
    logger.info(
      `Received TradingView alert for user ${userId}: ${JSON.stringify(
        alertData
      )}`
    );

    const result = await db.collection("alerts").insertOne({
      user_id: userId,
      webhook_data: JSON.stringify(alertData),
      sent_successfully: false,
      error_message: null,
      created_at: new Date(),
    });
    const alertId = result.insertedId.toString();

    if (!user.chat_id) {
      const errorMsg = `No chat configured for ${user.alert_type} alerts. Use ${user.auth_command} command first.`;
      await db
        .collection("alerts")
        .updateOne(
          { _id: new ObjectId(alertId) },
          { $set: { error_message: errorMsg } }
        );
      logger.error(
        `No chat ID for user ${userId}, alert type: ${user.alert_type}`
      );
      return res.status(400).json({ error: "Chat not configured" });
    }

    const telegramService = new TelegramService(user.bot_token);
    const formattedMessage = telegramService.formatTradingviewAlert(alertData);
    const sendResult = await telegramService.sendMessage(
      user.chat_id,
      formattedMessage
    );

    await db.collection("alerts").updateOne(
      { _id: new ObjectId(alertId) },
      {
        $set: {
          sent_successfully: sendResult.success,
          error_message: sendResult.error || null,
        },
      }
    );

    res.json({ status: "ok", sent: sendResult.success });
  } catch (error) {
    logger.error(`Error processing TradingView webhook: ${error}`);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/api/webhook/telegram/:userId", async (req, res) => {
  console.log(
    "Received POST /api/webhook/telegram/:userId:",
    req.params.userId
  );
  const { userId } = req.params;
  try {
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const update = req.body;
    logger.debug(`Received Telegram update: ${JSON.stringify(update)}`);

    if (!update.message) {
      return res.json({ status: "ok" });
    }

    const { text, chat } = update.message;
    const chatId = String(chat.id);
    const chatType = chat.type;

    if (text === user.auth_command) {
      logger.info(
        `Received correct auth command from chat ${chatId}, type: ${chatType}`
      );
      await db
        .collection("users")
        .updateOne(
          { _id: new ObjectId(userId) },
          { $set: { chat_id: chatId } }
        );

      const telegramService = new TelegramService(user.bot_token);
      let welcomeMessage = `🤖 <b>Bot Authenticated Successfully!</b>\n\nYour bot <b>@${user.bot_username}</b> is now ready to send TradingView alerts to this `;
      welcomeMessage +=
        chatType === "private"
          ? "private chat."
          : chatType === "group" || chatType === "supergroup"
          ? "group."
          : chatType === "channel"
          ? "channel."
          : "chat.";
      welcomeMessage += `\n\n📋 <b>Next Steps:</b>\n1️⃣ Copy your webhook URL from the dashboard\n2️⃣ Add it to your TradingView alert settings\n3️⃣ Start receiving alerts automatically!\n\n🔗 Dashboard: https://xat-fg8p.onrender.com/dashboard?user_id=${userId}`;
      await telegramService.sendMessage(chatId, welcomeMessage);
      logger.info(`Chat ${chatId} configured for user ${userId}`);
    } else if (text === "/start" && chatType === "private") {
      const telegramService = new TelegramService(user.bot_token);
      const startMessage = `👋 <b>Welcome to @${user.bot_username}!</b>\n\nThis bot is ready to send you TradingView alerts.\n\n📋 <b>To authenticate and start receiving alerts:</b>\nSend this command: <code>${user.auth_command}</code>\n\n🔗 Dashboard: https://xat-fg8p.onrender.com/dashboard?user_id=${userId}`;
      await telegramService.sendMessage(chatId, startMessage);
    }

    res.json({ status: "ok" });
  } catch (error) {
    logger.error(`Error processing Telegram webhook: ${error}`);
    res.status(500).json({ status: "error" });
  }
});

app.post("/api/user/:userId/regenerate_secret", async (req, res) => {
  console.log(
    "Received POST /api/user/:userId/regenerate_secret:",
    req.params.userId
  );
  const { userId } = req.params;
  try {
    await db
      .collection("users")
      .updateOne(
        { _id: new ObjectId(userId) },
        { $set: { secret_key: uuidv4() } }
      );
    res.json({ status: "ok" });
  } catch (error) {
    logger.error(`Error regenerating secret: ${error}`);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.use((req, res) => {
  res
    .status(404)
    .send(
      "<h1>Page Not Found</h1><p>The requested page could not be found.</p>"
    );
});

app.use((err, req, res, next) => {
  logger.error(`Server error: ${err}`);
  res
    .status(500)
    .send("<h1>Internal Server Error</h1><p>An unexpected error occurred.</p>");
});

const startServer = async () => {
  try {
    await initDatabase();
    const port = process.env.PORT || 5000;
    app.listen(port, () => {
      console.log(`🚀 Starting TradingView Telegram Bot Integration Server...`);
      console.log(
        `📡 Server will be available at: https://xat-fg8p.onrender.com`
      );
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

startServer();
