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


const setup = async (req, res) => {
  try {
    const { bot_token, image, XId } = req.body;
    if (!bot_token || !bot_token.trim() || !XId || !XId.trim()) {
      flashMessage(req, "Bot token and XId are required", "error");
      return res.status(400).json({
        error: "Bot token and XId are required\n\nPowered by xalgos.in",
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
      return res
        .status(400)
        .json({ error: "Invalid bot token\n\nPowered by xalgos.in" });
    }

    let userId;
    let existingUser;
    let attempts = 0;
    const maxAttempts = 10;

    do {
      const userCount = await db.collection("users").countDocuments();
      userId = userCount + 1;
      existingUser = await db.collection("users").findOne({ XalgoID: XId });
      attempts++;
      if (attempts > maxAttempts) {
        flashMessage(req, "Unable to assign a unique user ID.", "error");
        return res.status(500).json({
          error: "Unable to assign a unique user ID\n\nPowered by xalgos.in",
        });
      }
    } while (existingUser && existingUser.XalgoID === XId);

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
    await db.collection("users").insertOne(userData);
    await telegramService.setWebhook(webhookUrl);

    const userAlerts = await db
      .collection("alerts")
      .find({ userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .toArray();

    const webhookTradingViewUrl = `${protocol}://${host}/webhook/tradingview/${userId}/${secretKey}`;

    flashMessage(req, "Bot configured successfully!", "success");
    res.json({
      redirect: `/dashboard/${userId}`,
      flashMessages: getFlashMessages(req),
      userData,
      recentAlerts: userAlerts,
      webhookUrl: webhookTradingViewUrl,
    });
  } catch (error) {
    console.error("Error in setup:", error.message, error.stack);
    flashMessage(req, "An error occurred while setting up the bot", "error");
    return res
      .status(500)
      .json({ error: "Internal server error\n\nPowered by xalgos.in" });
  }
};

module.exports = setup;
