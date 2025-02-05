import swaggerJsdoc from 'swagger-jsdoc';
import { version } from '../../package.json';
import { allUserDocs } from '../docs/index';
import dotenv from "dotenv";

dotenv.config()

const swaggerOptions: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.1.0',
    info: {
      title: 'Korex-restaurant Express API with Swagger',
      version: version,
      description: 'OpenAPI documentation for the Korex-restaurant project',
    },
    servers: [
      {
        url: `http://localhost:${process.env.PORT}/`,
        description: 'Local server',
      },
      {
        url: 'https://korex-restaurant.vercel.app/',
        description: 'Live server',
      },
    ],

    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      {
        bearerAuth: [],
      },
    ],
    paths: {
      ...allUserDocs.paths,
    },
  },
  apis: [],
};

export const specs = swaggerJsdoc(swaggerOptions);
