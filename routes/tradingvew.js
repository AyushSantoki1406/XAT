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

const tradingview = async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const secretKey = req.params.secretKey;
    const userData = await db.collection("users").findOne({ id: userId });

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
      await db.collection("alerts").insertOne({
        userId,
        webhookData,
        contentType,
        sentSuccessfully: false,
        createdAt: new Date(),
        errorMessage: errorMsg,
      });
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
      : res
          .status(500)
          .json({ error: "Failed to send alert\n\nPowered by xalgos.in" });
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
    return res
      .status(500)
      .json({ error: "Internal server error\n\nPowered by xalgos.in" });
  }
};
module.exports = tradingview;
