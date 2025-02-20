import { z } from 'zod';

const regex =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$/;

const registerSchema = z.object({
  name: z.string().min(1, 'Name is required').max(30),
  email: z.string().email().trim().min(1, 'Email is required'),
  password: z
    .string()
    .regex(
      regex,
      'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character'
    ),
});

const forgetPwdSchema = z.object({
  email: z.string().email().trim().min(1, 'Email is required'),
});

const verifyOtpSchema = z.object({
  otp: z.string().min(1, 'Otp is required').max(6),
});

const resetPasswordSchema = z.object({
  newPassword: z
    .string()
    .regex(
      regex,
      'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character'
    ),
});

const loginSchema = z.object({
  email: z.string().email().trim().min(1, 'Email is required'),
  password: z
    .string()
    .regex(
      regex,
      'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character'
    ),
});

export default {
  registerSchema,
  forgetPwdSchema,
  verifyOtpSchema,
  resetPasswordSchema,
  loginSchema,
};
