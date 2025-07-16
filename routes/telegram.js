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

const telegram = async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    console.log(
      `Received Telegram update for userId ${userId}:`,
      JSON.stringify(req.body, null, 2)
    );

    const userData = await db.collection("users").findOne({ id: userId });
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
          await db
            .collection("users")
            .updateOne({ id: userId }, { $set: { chatId: String(chat.id) } });
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
          process.env.HMAC_SECRET || "3HKlcLqdkJmvjhoAf8FnYzr4Ua6QBWtG";
        const hmac = crypto.createHmac("sha256", secret);
        hmac.update(`${userId}`);
        const expectedEncodedData = hmac.digest("base64");

        if (encodedData === expectedEncodedData) {
          await db
            .collection("users")
            .updateOne({ id: userId }, { $set: { chatId: String(chat.id) } });
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
    console.error("Error in telegram webhook:", error.message, error.stack);
    return res
      .status(500)
      .json({ error: "Internal server error\n\nPowered by xalgos.in" });
  }
};
module.exports = telegram;
