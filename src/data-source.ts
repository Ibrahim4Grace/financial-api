import 'reflect-metadata';
import 'dotenv/config';
import { DataSource } from 'typeorm';
import { User } from './entity/user';
import { Admin } from './entity/admin';

export const AppDataSource = new DataSource({
  type: 'postgres',
  host: process.env.POSTGRESDB_HOST,
  port: Number(process.env.POSTGRESDB_PORT),
  username: process.env.POSTGRESDB_USER,
  password: process.env.POSTGRESDB_PASSWORD,
  database: process.env.POSTGRESDB_DATABASE,
  synchronize: false,
  logging: true,
  // logging: ['error', 'warn'],
  entities: [User, Admin],
  // entities: ['src/entity/**/*.ts'],
  migrations: ['src/migrations/**/*.ts'],
  subscribers: [],
});

console.log('Database connection options:', {
  host: process.env.POSTGRESDB_HOST,
  port: process.env.POSTGRESDB_PORT,
  username: process.env.POSTGRESDB_USER,
  database: process.env.POSTGRESDB_DATABASE,
});

// export async function initializeDataSource() {
//   if (!AppDataSource.isInitialized) {
//     await AppDataSource.initialize()
//       .then((dataSource) => {
//         console.log('dataSource', dataSource);
//       })
//       .catch((error) => {
//         console.log('error', error);
//       });
//   }
//   return AppDataSource;
// }
