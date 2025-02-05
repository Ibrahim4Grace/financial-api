import { Router, Request, Response, NextFunction } from 'express';
import { UserService } from '../services';
import { User } from '../entity';
import { RegisterUserto } from '../types';
import { TokenService } from '../utils';
import {
  validateData,
  sendJsonResponse,
  asyncHandler,
  ResourceNotFound,
  BadRequest,
  // authMiddleware,
  // getCurrentUser,
} from '../middlewares';

class UserController {
  private userService = new UserService();
}

export const userController = new UserController();
