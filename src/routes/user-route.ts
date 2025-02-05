import { Router } from 'express';
import {} from '../controllers';

const userRoute = Router();

userRoute.post('/auth/google');

export default userRoute;
