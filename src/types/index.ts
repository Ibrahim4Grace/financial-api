import { User, Admin } from '../entities';

export interface IUser {
  id: string;
  name: string;
  email: string;
  password: string;
  isEmailVerified: boolean;
  failedLoginAttempts: number;
  isLocked: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface RegisterUserto {
  name: string;
  email: string;
  password: string;
}

export interface RegistrationResponse {
  user: Partial<IUser>;
  verificationToken: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
  role?: string;
}

export interface loginResponse {
  user: Partial<IUser>;
  token: string;
}

export interface EmailVerificationPayload {
  userId: string;
  email: string;
}

export interface EmailData {
  from: string;
  to: string;
  subject: string;
  html: string;
}
export interface JwtPayload {
  userId: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: {
        user_id: string;
        role: string;
        email: string;
        name: string;
      };
      currentUser?: User | Admin;
    }
  }
}

// export interface AuthenticatedUser {
//   userId: string;
//   email: string;
//   name: string;
// }

// export interface IPasswordHistoryEntry {
//   password: string;
//   changedAt: Date;
// }
