import { User } from "../models/User.js";

class UserController {
  async getMe(req, res) {
    try {
      const user = await User.findById(req.userId);
      res.json(user);
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

export default new UserController();