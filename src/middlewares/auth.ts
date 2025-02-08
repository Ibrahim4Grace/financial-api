import { NextFunction, Request, Response } from 'express';
import { AppDataSource } from '../data-source';
import { User, Admin } from '../entities';
import { log, TokenService } from '../utils';
import { Repository } from 'typeorm';
import {
  asyncHandler,
  ResourceNotFound,
  ServerError,
  Unauthorized,
  Forbidden,
} from '../middlewares';

const extractToken = (req: Request): string | null => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.split(' ')[1];
};

export const authentication = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const token = extractToken(req);
    if (!token) {
      throw new Unauthorized('No token provided');
    }

    const payload = await TokenService.verifyAuthToken(token);
    log.info('decoded.userId:', payload.userId);

    const userRepository = AppDataSource.getRepository(User);
    const adminRepository = AppDataSource.getRepository(Admin);

    const user = await userRepository.findOne({
      where: { id: payload.userId },
    });
    const admin = !user
      ? await adminRepository.findOne({ where: { id: payload.userId } })
      : null;

    const currentUser = user || admin;
    if (!currentUser) {
      throw new Unauthorized('User not found');
    }

    req.user = {
      user_id: currentUser.id,
      email: currentUser.email,
      role: currentUser.role,
      name: currentUser.name,
    };
    console.log('Set req.user to:', req.user);

    next();
  } catch (error) {
    log.error(error);
    throw new ServerError('INTERNAL_SERVER_ERROR');
  }
};

export const authorization = (roles: string[]) =>
  asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user?.user_id;
    if (!userId) {
      throw new Unauthorized('User not authenticated');
    }

    const userRepository = AppDataSource.getRepository(User);
    const adminRepository = AppDataSource.getRepository(Admin);

    const user = await userRepository.findOne({ where: { id: userId } });
    const admin = !user
      ? await adminRepository.findOne({ where: { id: userId } })
      : null;

    const currentUser = user || admin;
    if (!currentUser) {
      throw new ResourceNotFound('User not found');
    }

    req.currentUser = currentUser;

    if (!roles.includes(currentUser.role)) {
      throw new Forbidden(`Access denied ${currentUser.role} isn't allowed`);
    }

    next();
  });
