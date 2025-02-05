import { Router } from 'express';
import {} from '@/controllers/index';

const userRoute = Router();

userRoute.post('/auth/google');

export default userRoute;
