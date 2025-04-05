import { body } from "express-validator";
import { createCustomValidatorMiddleware } from "./general.validator.js";

const firstName = body("firstName")
  .exists()
  .withMessage("Поле firstName обязательна!")
  .isString()
  .withMessage("Поле firstName должна быть строчкой!")
  .isLength({ min: 3 })
  .withMessage("Поле firstName должна содержать минимум 3 символа!");

const lastName = body("lastName")
  .exists()
  .withMessage("Поле lastName обязательна!")
  .isString()
  .withMessage("Поле lastName должна быть строчкой!")
  .isLength({ min: 3 })
  .withMessage("Поле lastName должна содержать минимум 3 символа!");

const email = body("email")
  .exists()
  .withMessage("Поле email обязательна!")
  .isEmail()
  .withMessage("Поле email должно иметь в себе символ '@'!");

const password = body("password")
  .exists()
  .withMessage("Поле password обязательна!")
  .isString()
  .withMessage("Поле password должна быть строчкой!")
  .isStrongPassword()
  .withMessage("Ваш пароль слишком простой!");

export const registerValidator = createCustomValidatorMiddleware([
  firstName,
  lastName,
  email,
  password
]);

export const loginValidator = createCustomValidatorMiddleware([
  email,
  password
]);