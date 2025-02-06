import 'reflect-metadata';
import 'dotenv/config';
import { DataSource } from 'typeorm';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.POSTGRESDB_HOST,
  port: Number(process.env.POSTGRESDB_PORT),
  username: process.env.POSTGRESDB_USER,
  password: process.env.POSTGRESDB_PASSWORD,
  database: process.env.POSTGRESDB_DATABASE,
  synchronize: false,
  logging: true,
  entities: ['src/entities/**/*.ts'],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: [],
});
