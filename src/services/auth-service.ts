import { User } from '../entities';
import bcrypt from 'bcryptjs';
import { AppDataSource } from '../data-source';
import { AuthUtils, EmailQueueService, TokenService } from '../utils';
import {
  IUser,
  RegisterUserto,
  RegistrationResponse,
  LoginCredentials,
  loginResponse,
} from '../types';
import {
  sendOTPByEmail,
  welcomeEmail,
  PasswordResetEmail,
} from '../email-templates';
import {
  Conflict,
  BadRequest,
  ResourceNotFound,
  Forbidden,
  Unauthorized,
} from '../middlewares';

export class AuthService {
  public userRepo = AppDataSource.getRepository(User);

  private async findUserByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email } });
  }

  private async verifyUserOtp(verificationToken: string): Promise<User | null> {
    return this.userRepo
      .createQueryBuilder('user')
      .where('user.emailVerificationOTP @> :token::jsonb', {
        token: JSON.stringify({ verificationToken }),
      })
      .getOne();
  }

  private sanitizeUser(user: IUser): Partial<IUser> {
    return {
      id: user.id,
      name: user.name,
      email: user.email,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };
  }

  public async register(
    payload: RegisterUserto
  ): Promise<RegistrationResponse> {
    const existingUser = await this.findUserByEmail(payload.email);
    if (existingUser) {
      throw new Conflict('User with this email already exists');
    }

    const user = this.userRepo.create({
      ...payload,
    });
    const newUser = await this.userRepo.save(user);

    const { otp, verificationToken } =
      await AuthUtils.generateEmailVerificationOTP(newUser.id, newUser.email);

    const emailOptions = sendOTPByEmail(newUser, otp);
    await EmailQueueService.addEmailToQueue(emailOptions);

    return {
      user: this.sanitizeUser(user),
      verificationToken: verificationToken,
    };
  }

  public async verifyRegistrationOTP(
    verificationToken: string,
    otp: string
  ): Promise<IUser> {
    console.log('Verification Token:', verificationToken); // Log the token
    console.log('OTP:', otp); // Log the OTP

    const validateUser = await this.verifyUserOtp(verificationToken);
    console.log('Validated User:', validateUser); // Log the validated user

    if (!validateUser) {
      throw new BadRequest('Invalid or expired verification session');
    }

    const tokenPayload = await TokenService.verifyEmailToken(verificationToken);
    console.log('Token Payload:', tokenPayload); // Log the token payload
    if (!tokenPayload || !tokenPayload.email) {
      throw new BadRequest('Invalid or expired reset token');
    }

    const user = await this.findUserByEmail(tokenPayload.email);
    if (!user) {
      throw new BadRequest('Invalid or expired reset token');
    }

    if (!user.emailVerificationOTP?.otp) {
      throw new BadRequest('No OTP found for this user');
    }

    if (new Date() > user.emailVerificationOTP.expiresAt) {
      throw new BadRequest('Verification session has expired');
    }
    const isValid = await bcrypt.compare(
      otp,
      user.emailVerificationOTP.otp.toString()
    );
    if (!isValid) {
      throw new BadRequest('Invalid OTP');
    }

    user.emailVerificationOTP = null;
    user.isEmailVerified = true;
    await this.userRepo.save(user);

    const emailOptions = welcomeEmail(user);
    await EmailQueueService.addEmailToQueue(emailOptions);

    return user;
  }

  public async forgotPassword(email: string): Promise<string> {
    console.log('Email received:', email);
    const user = await this.findUserByEmail(email);
    console.log('User found:', user);

    if (!user) {
      throw new ResourceNotFound('User not found');
    }
    const { otp, verificationToken } =
      await AuthUtils.generateEmailVerificationOTP(user.id, user.email);

    await this.userRepo.save(user);

    const emailOptions = sendOTPByEmail(user, otp);
    await EmailQueueService.addEmailToQueue(emailOptions);

    return verificationToken;
  }

  public async verifyResetPasswordOTP(
    verificationToken: string,
    otp: string
  ): Promise<IUser> {
    const validateUser = await this.verifyUserOtp(verificationToken);
    if (!validateUser) {
      throw new BadRequest('Invalid or expired verification session');
    }

    const payload = await TokenService.verifyEmailToken(verificationToken);
    if (!payload || !payload.email) {
      throw new BadRequest('Invalid or expired reset token');
    }

    const user = await this.findUserByEmail(payload.email);
    if (!user) {
      throw new BadRequest('Invalid or expired reset token');
    }

    if (!user.emailVerificationOTP?.otp) {
      throw new BadRequest('No OTP found for this user');
    }

    if (new Date() > user.emailVerificationOTP.expiresAt) {
      throw new BadRequest('Verification session has expired');
    }

    const isValid = await bcrypt.compare(
      otp,
      user.emailVerificationOTP.otp.toString()
    );
    if (!isValid) {
      throw new BadRequest('Invalid OTP');
    }

    return user;
  }

  public async resetPassword(
    verificationToken: string,
    newPassword: string
  ): Promise<void> {
    const validateUser = await this.verifyUserOtp(verificationToken);
    if (validateUser) {
      throw new BadRequest('Invalid or expired verification session');
    }

    const payload = await TokenService.verifyEmailToken(verificationToken);
    if (!payload || !payload.email) {
      throw new BadRequest('Invalid or expired reset token');
    }

    const user = await this.findUserByEmail(payload.email);
    if (!user) {
      throw new BadRequest('Invalid or expired reset token');
    }

    // Add the old password to history before updating
    user.passwordHistory = user.passwordHistory ?? [];
    const isPasswordUsedBefore = user.passwordHistory.some((entry) =>
      bcrypt.compareSync(newPassword, entry.password)
    );

    if (isPasswordUsedBefore) {
      throw new BadRequest(
        'This password has been used before. Please choose a new password.'
      );
    }

    user.passwordHistory.push({
      password: user.password,
      changedAt: new Date(),
    });

    const PASSWORD_HISTORY_LIMIT = 5;
    if (user.passwordHistory.length > PASSWORD_HISTORY_LIMIT) {
      user.passwordHistory = user.passwordHistory.slice(
        -PASSWORD_HISTORY_LIMIT
      );
    }

    user.password = newPassword;
    user.emailVerificationOTP = null;
    user.failedLoginAttempts = 0;
    user.isLocked = false;
    await this.userRepo.save(user);

    const emailOptions = PasswordResetEmail(user);
    await EmailQueueService.addEmailToQueue(emailOptions);
  }

  public async login(credentials: LoginCredentials): Promise<loginResponse> {
    const user = await this.findUserByEmail(credentials.email);
    if (!user) {
      throw new ResourceNotFound('Invalid email or password');
    }

    if (!user.isEmailVerified) {
      throw new Forbidden('Verify your email before sign in.');
    }

    const isValid = await user.comparePassword(credentials.password);
    if (!isValid) {
      user.failedLoginAttempts += 1;
      if (user.failedLoginAttempts >= 3) {
        user.isLocked = true;
        await this.userRepo.save(user);
        throw new Forbidden(
          'Your account has been locked due to multiple failed login attempts. Please reset your password.'
        );
      }
      await this.userRepo.save(user);
      throw new Unauthorized('Invalid email or password');
    }

    user.failedLoginAttempts = 0;
    await this.userRepo.save(user);

    const requestedRole = credentials.role || 'user';
    if (!user.role.includes(requestedRole)) {
      throw new Forbidden(
        `You do not have permission to sign in as ${requestedRole}`
      );
    }

    const token = TokenService.createAuthToken({
      userId: user.id,
      role: user.role,
    });

    return {
      user: this.sanitizeUser(user),
      token,
    };
  }
}
