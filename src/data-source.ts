import 'reflect-metadata';
import 'dotenv/config';
import { DataSource } from 'typeorm';
import { User } from './entity/user';
import { Admin } from './entity/admin';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.POSTGRESDB_HOST,
  port: parseInt(process.env.POSTGRESDB_PORT),
  username: process.env.POSTGRESDB_USER,
  password: process.env.POSTGRESDB_PASSWORD,
  database: process.env.POSTGRESDB_DATABASE,
  synchronize: false,
  logging: true,
  // logging: ['error', 'warn'],
  entities: [User, Admin],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: [],
});

export const userRepo = AppDataSource.getRepository(User);
