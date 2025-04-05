import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
//Swager Schema
import userSchema from "./docs/schemas/user.js";
import postSchema from "./docs/schemas/post.js";
//Swager Paths
import authPaths from  "./docs/paths/auth.js"
import postPaths from "./docs/paths/post.js";

const swaggerDoc = swaggerJSDoc({
    definition: {
        openapi: "3.1.1",
        info: {
            title: "Simple Blog Application",
            version: "1.0.0",
            description: "Список API для простого блога"
        },
        components: {
            schemas: {
                User: userSchema,
                Post: postSchema
            },
           securitySchemes: {
            BearerAuth: {
                type: "http",
                scheme: "bearer",
                bearerFormat: "JWT"
            }
           }
        } ,
        paths: {...authPaths, ...postPaths}
    },
    apis:[]
});

export function setupSwagger(app) {
    app.use("/docs",swaggerUi.serve, swaggerUi.setup(swaggerDoc) )
}