import { Request, Response, NextFunction } from 'express';
import { AuthService } from '../services';
import { RegisterUserto } from '../types';
import { TokenService } from '../utils';
import { sendJsonResponse, asyncHandler, BadRequest } from '../middlewares';

const authService = new AuthService();

export const register = asyncHandler(async (req: Request, res: Response) => {
  const result = await authService.register(req.body);
  sendJsonResponse(
    res,
    201,
    'Registration initiated. Please verify your email with the OTP sent.',
    result
  );
});

export const registrationOTP = asyncHandler(
  async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new BadRequest('Authorization token is required');
    }
    const token = authHeader.split(' ')[1];

    const { otp } = req.body;
    if (!otp) {
      throw new BadRequest('OTP code is required');
    }

    await authService.verifyRegistrationOTP(token, otp);

    sendJsonResponse(
      res,
      200,
      'Email verified successfully. You can now log in.'
    );
  }
);

export const forgotPassword = asyncHandler(
  async (req: Request, res: Response) => {
    const resetToken = await authService.forgotPassword(req.body);
    sendJsonResponse(
      res,
      200,
      'Reset token generated and OTP sent to your email.',
      resetToken
    );
  }
);

export const resetPasswordOTP = asyncHandler(
  async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new BadRequest('Authorization token is required');
    }
    const resetToken = authHeader.split(' ')[1];

    const { otp } = req.body;
    if (!otp) {
      throw new BadRequest('OTP is required');
    }

    await authService.verifyResetPasswordOTP(resetToken, otp);
    sendJsonResponse(
      res,
      200,
      'OTP verified successfully. You can now reset your password.'
    );
  }
);

export const resetPassword = asyncHandler(
  async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new BadRequest('Authorization token is required');
    }
    const resetToken = authHeader.split(' ')[1];

    const { newPassword } = req.body;
    if (!newPassword) {
      throw new BadRequest('New password is required');
    }

    await authService.resetPassword(resetToken, newPassword);
    sendJsonResponse(res, 200, 'Password reset successfully.');
  }
);

export const login = asyncHandler(async (req: Request, res: Response) => {
  const result = await authService.login(req.body);
  sendJsonResponse(res, 200, 'Login successful', result);
});
