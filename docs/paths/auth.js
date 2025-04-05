import { request } from "express";

const authPaths = {
    "/auth/register": {
        post: {
            summary: "New user registration",
            tags: ["Auth"],
            responses: {
                201: {
                    description: "This route return new user data"
                }
            },
            requestBody: {
                required: true,
                content: {
                    "application/json": {
                        schema: {
                            type: "object",
                            properties: {
                                firstName: {
                                    type: "string",
                                    example: "John"
                                },
                                lastName: {
                                    type: "string",
                                    example:"Doe"
                                },
                                email: {
                                    type: "string",
                                    description: "Email address of user",
                                    example: "example@mail.kz"
                                },
                                password: {
                                    type: "string",
                                    description: "Hashed password by bcript.js",
                                    example: "Qwerty123!"
                                }
                            }
                        }
                    }
                }
            }
        }
    },

    "/auth/login": {
        post: {
            summary: "Login user",
            tags: ["Auth"],
            responses: {
                200: {
                    description: "This route return JWT"
                }
            },
            requestBody: {
                required: true,
                content: {
                    "application/json": {
                        schema: {
                            type: "object",
                            properties: {
                               
                                email: {
                                    type: "string",
                                    description: "Email address of user",
                                    example: "example@mail.kz"
                                },
                                password: {
                                    type: "string",
                                    description: "Hashed password by bcript.js",
                                    example: "Qwerty123!"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

export default authPaths