import { User } from "../models/User.js"; 
import { hashPassword, checkValidPassword } from "../services/bcrypt.js";
import jwt from "jsonwebtoken";

class AuthController {
  async register(req, res) {
    try {
      const { firstName, lastName, email, password, isManager } = req.body;

      const emailAlreadyExist = await User.findOne({ email }) ;
      if(emailAlreadyExist)  {
        return res.status(409).json({ message: "Даная эл.почта занята!"})
      }
      
      const hashedPassword = await hashPassword(password)  

      const newUser = await new User({
        firstName,
        lastName,
        email,
        password: hashedPassword,
        isManager
      }).save(); 
      res.status(201).json({ user: newUser})
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  };

  async login(req, res) {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "Неверный email или пароль!"})
        }
      
       const passwordIsValid = await checkValidPassword(password, user.password);
       if (!passwordIsValid) {
        return res.status(404).json({ message: "Неверный email или пароль!"})
       };

       const token = jwt.sign(
        { userId: user._id, isManager: user.isManager } ,//Payload
        "secretkey", // Secret key
        { expiresIn: "12h" } // Expires in
       );
       res.json({ token})
        
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
}

export default new AuthController();
