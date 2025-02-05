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
  comparePassword(password: string): Promise<boolean>;
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

export interface AuthenticatedUser {
  userId: string;
  email: string;
  name: string;
}

// export interface IUserLogin {
//   email: string;
//   password: string;
// }

// export interface EmailTemplate {
//   subject: string;
//   template: string;
// }

// export interface IPasswordHistoryEntry {
//   password: string;
//   changedAt: Date;
// }

// export interface emailVerificationOTP {
//   otp: String;
//   expiresAt: Date;
//   verificationToken: String;
// }
