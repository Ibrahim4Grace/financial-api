import { Router } from 'express';
import * as authCtlr from '../controllers';
import { validateData } from '../middlewares';
import validate from '../schemas/auth-validation';

const authRoute = Router();

authRoute.post(
  '/register',
  validateData(validate.registerSchema),
  authCtlr.register
);
authRoute.post(
  '/verify-otp',
  validateData(validate.verifyOtpSchema),
  authCtlr.registrationOTP
);

authRoute.post(
  '/forgot',
  validateData(validate.forgetPwdSchema),
  authCtlr.forgotPassword
);
authRoute.post(
  '/password/verify-otp',
  validateData(validate.verifyOtpSchema),
  authCtlr.resetPasswordOTP
);
authRoute.post(
  '/password/reset',
  validateData(validate.resetPasswordSchema),
  authCtlr.resetPassword
);
authRoute.post('/login', validateData(validate.loginSchema), authCtlr.login);
export default authRoute;
