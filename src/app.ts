import express, { Request, Response } from 'express';
import cors from 'cors';
import 'module-alias/register';
import swaggerUi from 'swagger-ui-express';
import dotenv from 'dotenv';
import { errorHandler, routeNotFound } from '@/middlewares/index';
import { corsOptions, specs, closeRabbitMQ } from '@/configs/index';
import { router } from '@/routes/index';
import { AppDataSource } from './data-source';
import { EmailQueueService } from '@/utils/index';
import { log } from '@/utils/index';

dotenv.config();

const app = express();

app.use(cors(corsOptions));
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));
app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(specs));

// Routes
app.use('/api/v1', router);

const initializeRabbitMQ = async (): Promise<void> => {
  try {
    await EmailQueueService.initializeEmailQueue();
    await EmailQueueService.consumeEmails();
    log.info('RabbitMQ initialized successfully');
  } catch (error) {
    log.error('Failed to initialize RabbitMQ:', error);
    process.exit(1);
  }
};

app.get('/', (req: Request, res: Response) => {
  res.send('Ts  Authentication');
});

// Error handling middlewares
app.use(errorHandler);
app.use(routeNotFound);

const setupGracefulShutdown = (): void => {
  const shutdown = async (signal: string) => {
    log.info(`${signal} received. Shutting down gracefully...`);
    try {
      await closeRabbitMQ();
      log.info('RabbitMQ connection closed');
      process.exit(0);
    } catch (error) {
      log.error('Error during shutdown:', error);
      process.exit(1);
    }
  };

  ['SIGINT', 'SIGTERM'].forEach((signal) =>
    process.on(signal, () => shutdown(signal))
  );
};

const start = async () => {
  const port = process.env.PORT || 3000;
  await AppDataSource.initialize();
  await initializeRabbitMQ();
  setupGracefulShutdown();
  app.listen(port, () => console.log(`App listening on port ${port}!`));
};

start();
