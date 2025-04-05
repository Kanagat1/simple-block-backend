import { Post } from "../models/Post.js";

class PostController {
  async create(req, res) {
    try {
      const { title, text, isPublic } = req.body;
      const newUser = new Post({ title, text, isPublic });
      const result = await newUser.save();
      res.status(201).json(result);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getPublicPosts(req, res) {
    try {
      const posts = await Post.find({ isPublic: true });
      res.json(posts);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getAllPosts(req, res) {
    try {
      console.log(req.userId, req.isManager);
      const posts = await Post.find();
      res.json(posts);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async getPostById(req, res) {
    try {
      const { id } = req.params;
      const post = await Post.findById(id);

      if (!post) {
        return res.status(404).json({ error: "Пост не найден" });
      }

      res.json(post);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async update(req, res) {
    try {
      const { id } = req.params;
      const { title, text, isPublic } = req.body;

      const updatedPost = await Post.findByIdAndUpdate(
        id,
        { title, text, isPublic },
        { new: true }
      );

      if (!updatedPost) {
        return res.status(404).json({ error: "Пост не найден" });
      }

      res.json(updatedPost);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }

  async delete(req, res) {
    try {
      const { id } = req.params;
      const deletedPost = await Post.findByIdAndDelete(id);

      if (!deletedPost) {
        return res.status(404).json({ error: "Post not found" });
      }

      res.status(204).json({ message: "Пост был успешно удален" });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

export default new PostController();