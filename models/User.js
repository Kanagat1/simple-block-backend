import mongoose from "mongoose";



const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    trim: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  isManager: {
    type: Boolean, 
    required: true,
    default: false
  }
});

export const User = mongoose.model("User", userSchema);