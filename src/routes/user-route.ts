import { Router } from 'express';
import { UserController } from '../controllers';
import { authentication, authorization } from '../middlewares';

const userRoute = Router();
const userController = new UserController();

userRoute.get(
  '/',
  authentication,
  authorization(['user']),
  userController.fetchUser
);

userRoute.put(
  '/',
  authentication,
  authorization(['user']),
  userController.updateUser
);

export default userRoute;
