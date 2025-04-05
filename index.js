import express from "express";
import cors from "cors";
import { connectDatabase } from "./config/db.js";
import userRoutes from "./routes/user.routes.js";
import postRoutes from "./routes/post.routes.js";
import authRoutes from "./routes/auth.routes.js";
import { setupSwagger } from "./swagger.js";

const app = express();
const PORT = 7000;

app.use(cors());
app.use(express.json());
app.use("/user", userRoutes);
app.use("/post", postRoutes);
app.use("/auth", authRoutes);

app.listen(PORT, async () => {
  await connectDatabase();
  setupSwagger(app);
  console.log(`Сервер запущен на http://localhost:${PORT}`);  
});