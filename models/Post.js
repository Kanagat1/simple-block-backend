import mongoose from "mongoose";

const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  text: {
    type: String,
    required: true,
    trim: true
  },
  isPublic: {
    type: Boolean,
    required: true,
    default: true
  }
});

export const Post = mongoose.model("Post", postSchema);