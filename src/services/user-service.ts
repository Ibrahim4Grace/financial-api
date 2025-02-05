import { User } from '../entity';
import { AppDataSource } from '../data-source';
import { TokenService } from '../utils';
import bcrypt from 'bcryptjs';
import { LoginCredentials } from '../types';
import {
  IUser,
  RegisterUserto,
  RegistrationResponse,
  loginResponse,
} from '../types';

import {
  Conflict,
  ResourceNotFound,
  BadRequest,
  Forbidden,
  Unauthorized,
} from '../middlewares';

export class UserService {
  private userRepository = AppDataSource.getRepository(User);

  private async findUserById(userId: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { id: userId } });
  }

  private sanitizeUser(user: IUser): Partial<IUser> {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }
}
