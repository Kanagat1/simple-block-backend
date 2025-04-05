const postSchema = {
    type: "object",
    properties: {
      _id: {
          type: "string"
      },
      title: {
          type: "string",
      },
      text: {
          type: "string",
      },
      isPublic: {
          type: "boolean"
      },
    }
  }
  
  export default postSchema