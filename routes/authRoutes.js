const express = require("express");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const path = require("path");
const Image = require("../model/Image");
const User = require("../model/User");
const jwt = require("jsonwebtoken");
const authMiddleWare = require("../middleWare/authMiddleWare");
const FoundItems = require("../model/FoundItems");
const LostItems = require("../model/LostItems");
const SavedItems = require("../model/SavedItems");
const Notifications = require("../model/Notifications");
const axios = require("axios");
const { v2: cloudinary } = require("cloudinary");
const streamifier = require("streamifier");

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

const router = express.Router();

// Configure multer to use memory storage
const upload = multer({ storage: multer.memoryStorage() });

// Helper function to upload to Cloudinary
const uploadToCloudinary = async (buffer, folder) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );

    // Create a readable stream from buffer
    const { Readable } = require("stream");
    const stream = Readable.from(buffer);
    stream.pipe(uploadStream);
  });
};
router.post(
  "/upload",
  upload.single("image"),
  authMiddleWare,
  async (req, res) => {
    try {
      if (!req.file) {
        return res
          .status(400)
          .json({ success: false, message: "No file uploaded" });
      }

      const uploadResult = await uploadToCloudinary(
        req.file.buffer,
        "lost-and-found/uploads"
      );

      const newImage = new Image({
        imageUrl: uploadResult.secure_url,
        cloudinaryId: uploadResult.public_id,
      });

      await newImage.save();
      res.json({ success: true, imageUrl: newImage.imageUrl });
    } catch (error) {
      console.error("Error uploading image:", error);
      res
        .status(500)
        .json({ success: false, message: "Error uploading image" });
    }
  }
);

router.get("/images", authMiddleWare, async (req, res) => {
  try {
    const images = await Image.find();
    res.json(images);
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching images" });
  }
});
router.delete("/delete-image/:id", authMiddleWare, async (req, res) => {
  try {
    const { id } = req.params;
    const image = await Image.findById(id);

    if (!image) {
      return res
        .status(404)
        .json({ success: false, message: "Image not found" });
    }

    // Delete from Cloudinary first
    if (image.cloudinaryId) {
      await cloudinary.uploader.destroy(image.cloudinaryId);
    }

    // Then delete from database
    await Image.findByIdAndDelete(id);
    res.json({ success: true, message: "Image deleted successfully" });
  } catch (error) {
    console.error("Error deleting image:", error);
    res.status(500).json({ success: false, message: "Error deleting image" });
  }
});
router.post(
  "/signup",
  upload.fields([
    { name: "profileImage" },
    { name: "frontCnic" },
    { name: "backCnic" },
  ]),
  async (req, res) => {
    const { name, email, password, phone, cnic, address, token } = req.body;

    // Basic validation
    if (!name || !email || !password || !phone || !cnic || !address || !token) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }

    try {
      // Verify reCAPTCHA
      const response = await axios.post(
        `https://www.google.com/recaptcha/api/siteverify`,
        null,
        {
          params: {
            secret: process.env.RECAPTCHA_SECRET,
            response: token,
          },
        }
      );

      if (!response.data.success) {
        return res
          .status(400)
          .json({ success: false, message: "reCAPTCHA failed" });
      }

      // Check for existing user
      const [existingEmail, existingCnic] = await Promise.all([
        User.findOne({ email }),
        User.findOne({ cnic }),
      ]);

      if (existingEmail)
        return res.status(400).json({ message: "Email is already registered" });
      if (existingCnic)
        return res.status(400).json({ message: "CNIC is already registered" });

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Upload files to Cloudinary
      const uploadFile = async (file) => {
        if (!file) return null;
        try {
          const result = await uploadToCloudinary(
            file[0].buffer,
            "lost-and-found/user-documents"
          );
          return result.secure_url;
        } catch (uploadError) {
          console.error("Cloudinary upload error:", uploadError);
          throw new Error("Failed to upload document");
        }
      };

      const [profileImage, frontCnic, backCnic] = await Promise.all([
        uploadFile(req.files["profileImage"]),
        uploadFile(req.files["frontCnic"]),
        uploadFile(req.files["backCnic"]),
      ]);

      // Create user
      const user = new User({
        name,
        email,
        password: hashedPassword,
        phone,
        cnic,
        address,
        profileImage,
        frontCnic,
        backCnic,
      });

      await user.save();

      // Send notification
      try {
        const newResponse = await fetch(
          `https://lost-and-found-backend-xi.vercel.app/auth/pushNotification`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              userId: user._id,
              title: "Account Verification Pending – Stay Updated!",
              message:   "Thank you for registering with us! Your account is currently under review by our admin team to ensure all details are accurate and complete. Please be assured that we are working diligently to process your request. To stay informed on the status of your account, we encourage you to check back daily for updates on your verification process. We appreciate your patience and look forward to providing you with an exceptional experience once your account is fully verified. Regards, The Lost and Found Team", // your full message here
            }),
          }
        );

        if (!newResponse.ok) {
          console.error("Notification failed:", await newResponse.text());
        }
      } catch (notificationError) {
        console.error("Notification error:", notificationError);
      }

      res
        .status(201)
        .json({ success: true, message: "Account created successfully", user });
    } catch (error) {
      console.error("Signup error:", error);
      res.status(500).json({
        success: false,
        message: error.message || "Signup failed",
        error: process.env.NODE_ENV === "development" ? error.stack : undefined,
      });
    }
  }
);

router.delete("/deleteUser/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    await User.findByIdAndDelete(userId);
    res.json({ message: "Deleted Successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/getUser/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const user = await User.findById(id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ user });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Server error" });
  }
});
router.put("/verifyUser/:id", authMiddleWare, async (req, res) => {
  try {
    const { id } = req.params;
    const { isVerified, message } = req.body;

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const updatedUser = await User.findByIdAndUpdate(
      id,
      { isVerified, message },
      { new: true }
    );

    res.json({ message: "User Status updated!" });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Server error" });
  }
});
router.get("/getAllUser", authMiddleWare, async (req, res) => {
  try {
    const user = await User.find();
    res.json({ user });
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "Server error" });
  }
});

router.post("/login", async (req, res) => {
  const { email, password, cnic, loginType } = req.body;
  try {
    let user;
    if (loginType === "email") {
      user = await User.findOne({ email });
    } else if (loginType === "cnic") {
      user = await User.findOne({ cnic });
    }
    if (!user) return res.status(400).json({ message: "User not found" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: "Invalid credentials" });
    const token = jwt.sign({ id: user._id }, process.env.SECRET_KEY, {
      expiresIn: "2h",
    });
    res.json({
      message: "Login Successful",
      success: true,
      token,
      userId: user._id,
      userName: user.name,
      role: user.role,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});
router.get("/search-found", authMiddleWare, async (req, res) => {
  try {
    const { city, category } = req.query;
    let query = {};

    if (city) query.city = new RegExp(city, "i");
    if (category) query.category = new RegExp(category, "i");

    const foundItems = await FoundItems.find(query);

    res.json({ success: true, foundItems });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Error searching in found items" });
  }
});
router.get("/search-lost", authMiddleWare, async (req, res) => {
  try {
    const { city, category } = req.query;
    let query = {};

    if (city) query.city = new RegExp(city, "i");
    if (category) query.category = new RegExp(category, "i");

    const lostItems = await LostItems.find(query);

    res.json({ success: true, lostItems });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Error searching in lost items" });
  }
});

router.get("/get-foundItems", authMiddleWare, async (req, res) => {
  try {
    const foundItems = await FoundItems.find().sort({ createdAt: -1 });
    res.json({ success: true, foundItems });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error searching items" });
  }
});
router.post("/get-foundItemsByIds", authMiddleWare, async (req, res) => {
  const { itemIds } = req.body; // itemIds should be an array
  try {
    const foundItems = await FoundItems.find({ _id: { $in: itemIds } }).sort({
      createdAt: -1,
    }); // give all the array of items belong to item ids
    res.json({ success: true, foundItems });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching items" });
  }
});
router.get("/get-foundItemById/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const foundItem = await FoundItems.findById(id); // correct method
    if (!foundItem) {
      return res
        .status(404)
        .json({ success: false, message: "Item not found" });
    }
    res.json({ success: true, foundItem });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error fetching item" });
  }
});

router.get("/get-lostItems", authMiddleWare, async (req, res) => {
  try {
    const lostItems = await LostItems.find().sort({ createdAt: -1 });
    res.json({ success: true, lostItems });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error searching items" });
  }
});
router.post(
  "/add-foundItems",
  upload.array("images"),
  authMiddleWare,
  async (req, res) => {
    const {
      userId,
      title,
      category,
      subCategory,
      brand,
      description,
      city,
      location,
      dateFound,
    } = req.body;

    if (!userId || !title || !category || !city || !dateFound) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    try {
      // Upload all images to Cloudinary
      const uploadPromises = req.files.map((file) =>
        uploadToCloudinary(file.buffer, "lost-and-found/found-items")
      );

      const uploadResults = await Promise.all(uploadPromises);
      const imageUrls = uploadResults.map((result) => result.secure_url);

      const item = new FoundItems({
        userId,
        title,
        category,
        subCategory,
        brand,
        description,
        city,
        location,
        dateFound,
        imageUrl: imageUrls,
      });

      await item.save();
      res.json({ success: true, item });
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .json({ success: false, message: "Error adding item", error });
    }
  }
);

router.put("/verifyLostItems/:id", async (req, res) => {
  const { id } = req.params;
  const { request } = req.body;

  try {
    const verifyItems = await LostItems.findByIdAndUpdate(
      id,
      { request },
      { new: true }
    );

    if (!verifyItems) {
      return res
        .status(404)
        .json({ success: false, message: "Lost Item  not found" });
    }

    res.json({ success: true, message: "Lost item verified", verifyItems });
  } catch (error) {
    console.error("Error updating Lost Items:", error);
    res
      .status(500)
      .json({ success: false, message: "Error updating Lost Items" });
  }
});

router.put("/verifyFoundItems/:id", async (req, res) => {
  const { id } = req.params;
  const { request } = req.body;

  try {
    const verifyItems = await FoundItems.findByIdAndUpdate(
      id,
      { request },
      { new: true }
    );

    if (!verifyItems) {
      return res
        .status(404)
        .json({ success: false, message: "Found Item  not found" });
    }

    res.json({ success: true, message: "Found item verified", verifyItems });
  } catch (error) {
    console.error("Error updating Found Items:", error);
    res
      .status(500)
      .json({ success: false, message: "Error updating Lost Items" });
  }
});
router.post(
  "/add-lostItems",
  upload.array("images"),
  authMiddleWare,
  async (req, res) => {
    const {
      userId,
      title,
      category,
      subCategory,
      brand,
      description,
      city,
      location,
      dateLost,
    } = req.body;

    if (!userId || !title || !category || !city || !dateLost) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    try {
      // Upload all images to Cloudinary
      const uploadPromises = req.files.map((file) =>
        uploadToCloudinary(file.buffer, "lost-and-found/lost-items")
      );

      const uploadResults = await Promise.all(uploadPromises);
      const imageUrls = uploadResults.map((result) => result.secure_url);

      const item = new LostItems({
        userId,
        title,
        category,
        subCategory,
        brand,
        description,
        city,
        location,
        dateLost,
        imageUrl: imageUrls,
      });

      await item.save();
      res.json({ success: true, item });
    } catch (error) {
      console.error(error);
      res
        .status(500)
        .json({ success: false, message: "Error adding item", error });
    }
  }
);
router.post("/pushNotification", async (req, res) => {
  const { userId, title, message } = req.body;
  try {
    const notification = new Notifications({
      userId,
      title,
      message,
    });
    await notification.save();
    res.json({ message: "Notification added successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error adding Notification", error });
  }
});
router.get("/get-notifications/:userId", async (req, res) => {
  const { userId } = req.params;
  try {
    const notifications = await Notifications.find({ userId }).sort({
      createdAt: -1,
    }); // Sorting by createdAt in descending order to get latest first
    res.json({ success: true, notifications });
  } catch (error) {
    console.error("Error getting user notifications:", error);
    res
      .status(500)
      .json({ success: false, message: "Error fetching notifications" });
  }
});

router.delete("/delete-notifications/:id", authMiddleWare, async (req, res) => {
  const { id } = req.params;
  try {
    const deletedNotification = await Notifications.findByIdAndDelete(id);

    if (!deletedNotification) {
      return res
        .status(404)
        .json({ success: false, message: "Notification not found" });
    }

    res.json({
      success: true,
      message: "Notification deleted successfully",
      deletedNotification,
    });
  } catch (error) {
    console.error("Error deleting user notification:", error);
    res
      .status(500)
      .json({ success: false, message: "Error deleting notification" });
  }
});
router.put("/seen-notifications/:id", authMiddleWare, async (req, res) => {
  const { id } = req.params;
  const { isRead } = req.body;

  try {
    const seenNotification = await Notifications.findByIdAndUpdate(
      id,
      { isRead: isRead },
      { new: true }
    );

    if (!seenNotification) {
      return res
        .status(404)
        .json({ success: false, message: "Notification not found" });
    }

    res.json({
      success: true,
      message: "Notification seen status updated",
      seenNotification,
      check: isRead,
    });
  } catch (error) {
    console.error("Error updating seen status of notification:", error);
    res
      .status(500)
      .json({ success: false, message: "Error updating notification status" });
  }
});

router.get("/get-lostItems", authMiddleWare, async (req, res) => {
  try {
    const lostItems = await LostItems.find();
    res.json({ success: true, lostItems });
  } catch (error) {
    res.status(500).json({ success: false, message: "Error searching items" });
  }
});
router.post("/postSavedItems", async (req, res) => {
  const { userId, itemId } = req.body;
  try {
    const savedItems = new SavedItems({
      userId,
      itemId,
    });
    await savedItems.save();
    res.json({ message: "SavedItems added successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error adding SavedItems", error });
  }
});
router.get("/get-savedItems", async (req, res) => {
  try {
    const saveditems = await SavedItems.find().sort({ createdAt: -1 });
    res.json({ success: true, saveditems });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Error searching saved items" });
  }
});
router.put("/delete-savedItems/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const saveditems = await SavedItems.findByIdAndUpdate(
      id,
      { isDeleted: true },
      { new: true }
    );
    res.json({ success: true, message: "Deleted" });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "Error searching saved items" });
  }
});
router.put("/save-item/:id", authMiddleWare, async (req, res) => {
  const { id } = req.params;
  const { isSaved } = req.body;

  try {
    const saved = await SavedItems.findByIdAndUpdate(
      id,
      { isSaved: isSaved },
      { new: true }
    );

    if (!saved) {
      return res
        .status(404)
        .json({ success: false, message: "Saved Item Not Found" });
    }

    res.json({ success: true, message: "Item Saved Status  updated", saved });
  } catch (error) {
    console.error("Error updating  status of Saved items:", error);
    res
      .status(500)
      .json({ success: false, message: "Error updating Saved Items status" });
  }
});

module.exports = router;
