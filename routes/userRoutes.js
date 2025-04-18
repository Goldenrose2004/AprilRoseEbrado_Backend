const express = require("express");
const { register, login, addUser, updateUser, deleteUser } = require("../controllers/userController");
const router = express.Router();

router.post("/register", register);
router.post("/login", login);
router.post("/", addUser);
router.put("/:id", updateUser);
router.delete("/:id", deleteUser);

module.exports = router;
