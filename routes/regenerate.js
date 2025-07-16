const regenerate = async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const userData = await db.collection("users").findOne({ id: userId });

    if (!userData) {
      flashMessage(req, "User not found", "error");
      return res
        .status(404)
        .json({ error: "User not found\n\nPowered by xalgos.in" });
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
    res
      .status(500)
      .json({ error: "Internal server error\n\nPowered by xalgos.in" });
  }
};
module.exports = regenerate;
