import express, { Request, Response } from 'express';
import cors from 'cors';
import swaggerUi from 'swagger-ui-express';
import dotenv from 'dotenv';
import { errorHandler, routeNotFound } from './middlewares';
import { corsOptions, specs, closeRabbitMQ } from './configs';
import { router } from './routes';
import { AppDataSource } from './data-source';
import { EmailQueueService } from './utils';
import { log } from './utils';

dotenv.config();

class App {
  private app: express.Application;

  constructor() {
    this.app = express();
    this.configureMiddleware();
    this.configureRoutes();
    this.configureErrorHandling();
  }

  private configureMiddleware(): void {
    this.app.use(cors(corsOptions));
    this.app.use(express.json({ limit: '15mb' }));
    this.app.use(express.urlencoded({ limit: '15mb', extended: true }));
    this.app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(specs));
  }

  private configureRoutes(): void {
    this.app.use('/api/v1', router);
    this.app.get('/', (req: Request, res: Response) => {
      res.send('Ts Typeorm Authentication');
    });
  }

  private configureErrorHandling(): void {
    this.app.use(errorHandler);
    this.app.use(routeNotFound);
  }

  private async initializeRabbitMQ(): Promise<void> {
    try {
      await EmailQueueService.initializeEmailQueue();
      await EmailQueueService.consumeEmails();
      log.info('RabbitMQ initialized successfully');
    } catch (error) {
      log.error('Failed to initialize RabbitMQ:', error);
      process.exit(1);
    }
  }

  private setupGracefulShutdown(): void {
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
  }

  public async start(): Promise<void> {
    const port = process.env.PORT || 3000;
    await AppDataSource.initialize();
    await this.initializeRabbitMQ();
    this.setupGracefulShutdown();
    this.app.listen(port, () => log.info(`App listening on port ${port}!`));
  }
}

const app = new App();
app.start();
