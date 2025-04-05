const userSchema = {
  type: "object",
  properties: {
    _id: {
        type: "string"
    },
    firstName: {
        type: "string"
    },
    lastName: {
        type: "string"
    },
    email: {
        type: "string",
        description: "Email address of user",
        example: "example@mail.kz"
    },
    password: {
        type: "string",
        description: "Hashed password by bcript.js"
    },
    isManager: {
        type: "boolean"
    },
  }
}

export default userSchema