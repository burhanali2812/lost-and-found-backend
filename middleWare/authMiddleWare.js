const jwt = require("jsonwebtoken");

const authMiddleWare = (req, res, next) => {
  const token = req.header("Authorization"); // This gets the "Authorization" header
  
  if (!token) {
    return res.status(401).json({ success: false, message: "Access denied. No token provided." });
  }

  try {
    // Split the "Bearer" prefix and verify the token
    const decoded = jwt.verify(token.split(" ")[1], process.env.SECRET_KEY);
    req.user = decoded.id;  // Attach the user id to the request
    next();  // Proceed to the next middleware/route handler
  } catch (error) {
    res.status(401).json({ success: false, message: "Invalid token." });
  }
};

module.exports = authMiddleWare;
