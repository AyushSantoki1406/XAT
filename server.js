const express = require("express");
const { setup } = require("./setup.js");

const app = express();
app.post("/api/setup", setup());

app.listen(0, () => {
  console.log("Server started");
});
