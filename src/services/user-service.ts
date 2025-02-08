import { User } from '../entities';
import { AppDataSource } from '../data-source';
import { IUser } from '../types';
import { ResourceNotFound } from '../middlewares';

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

  public async getCurrentUser(userId: string) {
    const user = await this.findUserById(userId);
    if (!user) {
      throw new ResourceNotFound('User not found');
    }

    return {
      user: this.sanitizeUser(user),
    };
  }

  public async updateCurrentUser(userId: string, userData: Partial<User>) {
    const user = await this.findUserById(userId);
    if (!user) {
      throw new ResourceNotFound('User not found');
    }

    // Update user properties
    Object.assign(user, userData);

    const updatedUser = await this.userRepository.save(user);

    return {
      user: this.sanitizeUser(updatedUser),
    };
  }
}
