 const postPaths = {
   "/post": {
    get: {
       summary: "Fetch all posts",
       tags: ["Post"],
       responses: {
        200: {
            description: "This route return all posts",
            content: {
                "application/json": {
                    schema: {
                        type: "array",
                        $ref: "#/components/schemas/Post",
                    }
                }
            }
        }
       },
       security: [
        {
            BearerAuth: []
        }
     ]
    }
   },
   "/post/public":{
    get: {
        summary: "Fetch all public posts",
        tags: ["Post"],
        responses: {
         200: {
             description: "This route return all public posts",
             content: {
                 "application/json": {
                     schema: {
                         type: "array",
                         $ref: "#/components/schemas/Post",
                     }
                 }
             }
         }
        }
    }
   },
   "/post/{id}": {
    get: {
        summary: "Fetch post by id",
        tags: ["Post"],
        responses: {
         200: {
             description: "This route return the selected post",
             content: {
                 "application/json": {
                     schema: {
                         type: "object",
                         $ref: "#/components/schemas/Post",
                     }
                 }
             }
         },

        
        },
        parameters: [
            {
          name: "id",
          in: "path",
          required: true,
          schema: {
            type: "string"
          }
         }
        ]
    }
   }

 }

 export default postPaths