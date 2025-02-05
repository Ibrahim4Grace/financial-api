import express from 'express';
const router = express.Router();

import authRoute from './auth-route';
import userRoute from './user-route';

router.use('/auth', authRoute);
router.use('/user', userRoute);

export { router };
