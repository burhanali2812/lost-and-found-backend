const jwt = require("jsonwebtoken");
const User = require("../model/User"); // Make sure the path is correct

const authMiddleWare = async (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    return res.status(401).json({ success: false, message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token.split(" ")[1], process.env.SECRET_KEY);

    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(401).json({ success: false, message: "User not found." });
    }

    req.user = user; 
    next();
  } catch (error) {
    res.status(401).json({ success: false, message: "Invalid token." });
  }
};

module.exports = authMiddleWare;
