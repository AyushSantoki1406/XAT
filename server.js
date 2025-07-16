const express = require("express");
const { setup } = require("./setup.js");

const app = express();
app.post("/api/setup", setup());

// Use the port Render (or any PaaS) provides
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
