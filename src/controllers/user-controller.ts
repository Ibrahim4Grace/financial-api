import { Router, Request, Response, NextFunction } from 'express';
import { UserService } from '@/services/index';
import { User } from '@/entity/index';
import { RegisterUserto } from '@/types/index';
// import { TokenService } from '@/utils/index';
import {
  validateData,
  sendJsonResponse,
  asyncHandler,
  ResourceNotFound,
  BadRequest,
  // authMiddleware,
  // getCurrentUser,
} from '@/middlewares/index';

class UserController {
  private userService = new UserService();
}

export const userController = new UserController();
