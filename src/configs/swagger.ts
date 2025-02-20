import swaggerJsdoc from 'swagger-jsdoc';
import { version } from '../../package.json';
import { allAuthDocs } from '../docs/index';
import dotenv from 'dotenv';

dotenv.config();

const swaggerOptions: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.1.0',
    info: {
      title: 'Ts authentication Express API with Swagger',
      version: version,
      description: 'OpenAPI documentation for the Ts authentication project',
    },
    servers: [
      {
        url: `http://localhost:${process.env.PORT}/`,
        description: 'Local server',
      },
      {
        url: 'https://authentication.vercel.app/',
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
      ...allAuthDocs.paths,
    },
  },
  apis: ['./src/controllers/**/*.ts'],
};

export const specs = swaggerJsdoc(swaggerOptions);
