import express from "express";
import PostController from "../controllers/post.controller.js";
import { authUser } from "../middlewares/auth.middleware.js";
import { checkIsManager } from "../middlewares/auth.middleware.js";

const router = express.Router();

router.get("/",authUser, PostController.getAllPosts);  
router.get("/public", PostController.getPublicPosts);
router.get("/:id", PostController.getPostById);
router.post("/", authUser, checkIsManager, PostController.create);
router.patch("/:id", PostController.update);
router.delete("/:id", PostController.delete);
 
export default router;   