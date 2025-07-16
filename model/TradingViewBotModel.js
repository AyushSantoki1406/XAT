const mongoose = require("mongoose");

const AlertSchema = new mongoose.Schema({
  alertType: {
    type: String,
    enum: ["personal", "group", "channel"],
    required: true,
  },
  authCommand: { type: String, required: true },
  webhookData: { type: mongoose.Mixed },
  contentType: { type: String },
  formattedMessage: { type: String },
  sentSuccessfully: { type: Boolean },
  createdAt: { type: Date, default: Date.now },
  errorMessage: { type: String },
});

const TradingViewBotSchema = new mongoose.Schema({
  id: { type: Number, required: true, unique: true },
  botToken: { type: String, required: true },
  botUsername: { type: String, required: true },
  image: { type: String },
  secretKey: { type: String, required: true },
  chatId: { type: String },
  alerts: [AlertSchema],
  XalgoID: { type: String, required: true },
  webhookURL: { type: String },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("TradingViewBot", TradingViewBotSchema);
