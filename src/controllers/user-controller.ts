import { Request, Response } from 'express';
import { UserService } from '../services';
import {
  sendJsonResponse,
  asyncHandler,
  ResourceNotFound,
} from '../middlewares';

export class UserController {
  private userService = new UserService();

  public fetchUser = asyncHandler(
    async (req: Request, res: Response): Promise<void> => {
      const userId = req.currentUser?.id;
      if (!userId) {
        throw new ResourceNotFound('User not found');
      }
      const user = await this.userService.getCurrentUser(userId);
      sendJsonResponse(res, 200, 'Profile retrieved successfully', user);
    }
  );

  public updateUser = asyncHandler(
    async (req: Request, res: Response): Promise<void> => {
      const userId = req.currentUser?.id;
      if (!userId) {
        throw new ResourceNotFound('User not found');
      }
      const userData = req.body;
      const user = await this.userService.updateCurrentUser(userId, userData);
      sendJsonResponse(res, 200, 'Profile updated successfully', user);
    }
  );
}
