import express, { Request, Response } from 'express';
import cors from 'cors';
import 'module-alias/register';
import swaggerUi from 'swagger-ui-express';
import dotenv from 'dotenv';
import { errorHandler, routeNotFound } from './middlewares';
import { corsOptions, specs, closeRabbitMQ } from './configs';
import { router } from './routes';
import { AppDataSource } from './data-source';
import { EmailQueueService } from './utils';
import { log } from './utils';

dotenv.config();


const app = express();

app.use(cors(corsOptions));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(specs));

// Routes
app.use('/api/v1', router);

// const initializeRabbitMQ = async (): Promise<void> => {
//   try {
//     await EmailQueueService.initializeEmailQueue();
//     await EmailQueueService.consumeEmails();
//     log.info('RabbitMQ initialized successfully');
//   } catch (error) {
//     log.error('Failed to initialize RabbitMQ:', error);
//     process.exit(1);
//   }
// };

app.get('/', (req: Request, res: Response) => {
  res.send('Ts  Authentication');
});

// Error handling middlewares
app.use(errorHandler);
app.use(routeNotFound);

// const setupGracefulShutdown = (): void => {
//   const shutdown = async (signal: string) => {
//     log.info(`${signal} received. Shutting down gracefully...`);
//     try {
//       await closeRabbitMQ();
//       log.info('RabbitMQ connection closed');
//       process.exit(0);
//     } catch (error) {
//       log.error('Error during shutdown:', error);
//       process.exit(1);
//     }
//   };

//   ['SIGINT', 'SIGTERM'].forEach((signal) =>
//     process.on(signal, () => shutdown(signal))
//   );
// };

const start = async () => {
  const port = process.env.PORT || 3000;
  // await AppDataSource.initialize();
  try {
    await AppDataSource.initialize();
    console.log('Data Source has been initialized!');
  } catch (error) {
    console.error('Error during Data Source initialization:', error);
    process.exit(1); // Exit the process if initialization fails
  }
  // await initializeRabbitMQ();
  // setupGracefulShutdown();
  app.listen(port, () => console.log(`App listening on port ${port}!`));
};

start();
