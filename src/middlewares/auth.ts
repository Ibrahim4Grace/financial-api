import { NextFunction, Request, Response } from 'express';
import { AppDataSource } from '../data-source';
import jwt from 'jsonwebtoken';
import { User } from '@/entity/index';
import { log } from '../utils/logger';
import { ServerError } from '@/middlewares/error';
import { JwtPayload, AuthenticatedUser } from '../types/index';
import { Repository } from 'typeorm';

// export const authMiddleware = async (
//   req: Request & { user?: AuthenticatedUser },
//   res: Response,
//   next: NextFunction
// ) => {
//   try {
//     const authHeader = req.headers.authorization;

//     if (!authHeader || !authHeader.startsWith('Bearer ')) {
//       return res.status(401).json({
//         status_code: '401',
//         success: false,
//         message: 'Invalid token',
//       });
//     }

//     const token = authHeader.split(' ')[1];
//     if (!token) {
//       return res.status(401).json({
//         status_code: '401',
//         success: false,
//         message: 'Invalid token',
//       });
//     }

//     const secret = process.env.JWT_SECRET;
//     if (!secret) {
//       return res.status(500).json({
//         status_code: '500',
//         success: false,
//         message: 'Internal server error',
//       });
//     }

//     jwt.verify(token, secret, async (err, decoded) => {
//       if (err || !decoded) {
//         return res.status(401).json({
//           status_code: '401',
//           success: false,
//           message: 'Invalid token',
//         });
//       }

//       log.info(decoded);

//       const { userId } = decoded as JwtPayload;
//       log.info(`user with id ${userId} is logged in`);

//       // const user = await User.findOne({
//       //   where: { id: user_id },
//       // });
//       const userRepository: Repository<User> =
//         AppDataSource.getRepository(User);
//       const user = await userRepository.findOne({ where: { id: userId } });

//       if (!user) {
//         return res.status(401).json({
//           status_code: '401',
//           success: false,
//           message: 'Invalid token',
//         });
//       }

//       req.user = {
//         email: user.email,
//         userId: user.id,
//         name: user.name,
//       };

//       next();
//     });
//   } catch (error) {
//     log.error(error);
//     throw new ServerError('INTERNAL_SERVER_ERROR');
//   }
// };
