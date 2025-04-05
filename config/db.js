import mongoose from "mongoose";
import "dotenv/config";

export async function connectDatabase() {
  try {
    await mongoose.connect(process.env.DB_URL);
    console.log("Подключено к базе данных!");
  } catch (error) {
    console.log("Error!");
  }
}