import express from "express";
import UserController from "../controllers/user.controller.js";
import { authUser } from "../middlewares/auth.middleware.js";

const router = express.Router();

router.get("/me", authUser, UserController.getMe);

export default router;