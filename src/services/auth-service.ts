import { User, Admin } from '../entity';
import bcrypt from 'bcryptjs';
import { Repository } from 'typeorm';
import { AppDataSource } from '../data-source';
import { generateEmailVerificationOTP, EmailQueueService } from '../utils';
import { IUser, RegisterUserto, RegistrationResponse } from '../types';
import { sendOTPByEmail } from '../email-templates';
import { Conflict, ResourceNotFound, } from '../middlewares';

export class AuthService {
  // public userRepo = AppDataSource.getRepository(User);
  // public adminRepo = AppDataSource.getRepository(Admin);

  // private async findUserByEmail(email: string): Promise<User | null> {
  //   return this.userRepository.findOne({ where: { email } });
  // }

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

    const userRepo = AppDataSource.getRepository(User);

    const { name, email, password } = payload;

    const user = new User();
    user.name = name;
    user.email = email;
    user.password = password;

    console.log(user);
    await userRepo.findOneBy({ email });
    await userRepo.save(user);

    // const existingUser = await this.findUserByEmail(registrationData.email);
    // if (existingUser) {
    //   throw new Conflict('User with this email already exists');
    // }
    // const userRepo = AppDataSource.getRepository(User);
    // const { name, email, password } = payload;

    // const user = new User();
    // user.name = name;
    // user.email = email;
    // user.password = password;
    // // const user = this.userRepo.create({ name, email, password });
    // // await this.userRepo.save(user);

    // await userRepo.save(user);

    // const user = await this.userRepo.create({
    //   ...registrationData,
    // });

    // Save the user to the database

    const { otp, verificationToken } = await generateEmailVerificationOTP(
      user.id,
      user.email
    );

    const emailOptions = sendOTPByEmail(user, otp);
    await EmailQueueService.addEmailToQueue(emailOptions);

    return {
      user: this.sanitizeUser(user),
      verificationToken: verificationToken,
    };
  }

  // public async verifyRegistrationOTP(
  //   userId: string,
  //   otp: string
  // ): Promise<IUser> {
  //   const user = await this.userRepository.findOne({
  //     where: {
  //       id: userId,
  //       isEmailVerified: false,
  //       emailVerificationOTP: {
  //         expiresAt: new Date(),
  //       },
  //     },
  //   });

  //   if (!user) {
  //     throw new BadRequest('Invalid or expired verification session');
  //   }

  //   if (!user?.emailVerificationOTP?.otp) {
  //     throw new BadRequest('No OTP found for this user');
  //   }

  //   if (new Date() > user.emailVerificationOTP.expiresAt) {
  //     throw new BadRequest('OTP has expired');
  //   }

  //   const isValid = await bcrypt.compare(
  //     otp,
  //     user.emailVerificationOTP.otp.toString()
  //   );
  //   if (!isValid) {
  //     throw new BadRequest('Invalid OTP');
  //   }

  //   user.emailVerificationOTP = null;
  //   user.isEmailVerified = true;
  //   await this.userRepository.save(user);

  //   const emailOptions = welcomeEmail(user);
  //   await EmailQueueService.addEmailToQueue(emailOptions);

  //   return user;
  // }

  // public async forgotPassword(email: string): Promise<string> {
  //   const user = await this.findUserByEmail(email.toLowerCase().trim());
  //   if (!user) {
  //     throw new ResourceNotFound('User not found');
  //   }
  //   const { otp, verificationToken } = await generateEmailVerificationOTP(
  //     user.id,
  //     user.email
  //   );

  //   await this.userRepository.save(user);

  //   const emailOptions = sendOTPByEmail(user, otp);
  //   await EmailQueueService.addEmailToQueue(emailOptions);

  //   return verificationToken;
  // }

  // public async verifyResetPasswordOTP(
  //   verificationToken: string,
  //   otp: string
  // ): Promise<IUser> {
  //   // const user = await this.userRepository.findOne({
  //   //   where: {
  //   //     emailVerificationOTP: {
  //   //       verificationToken: verificationToken,
  //   //       expiresAt: new Date(),
  //   //     },
  //   //   },
  //   // });

  //   // if (!user) {
  //   //   throw new BadRequest('Invalid or expired reset token');
  //   // }
  //   // Step 1: Verify the token and extract the payload
  //   const payload = await TokenService.verifyEmailToken(verificationToken);
  //   if (!payload || !payload.email) {
  //     throw new BadRequest('Invalid or expired reset token');
  //   }
  //   // Step 2: Find the user by email
  //   const user = await this.findUserByEmail(payload.email);
  //   if (!user) {
  //     throw new BadRequest('Invalid or expired reset token');
  //   }

  //   if (!user.emailVerificationOTP?.otp) {
  //     throw new BadRequest('No OTP found for this user');
  //   }

  //   if (new Date() > user.emailVerificationOTP.expiresAt) {
  //     throw new BadRequest('OTP has expired');
  //   }

  //   const isValid = await bcrypt.compare(
  //     otp,
  //     user.emailVerificationOTP.otp.toString()
  //   );
  //   if (!isValid) {
  //     throw new BadRequest('Invalid OTP');
  //   }

  //   return user;
  // }

  // public async resetPassword(
  //   verificationToken: string,
  //   newPassword: string
  // ): Promise<void> {
  //   // const user = await this.userRepository.findOne({
  //   //   where: {
  //   //     emailVerificationOTP: {
  //   //       verificationToken: verificationToken,
  //   //       expiresAt: new Date(),
  //   //     },
  //   //   },
  //   // });

  //   // if (!user) {
  //   //   throw new BadRequest('Invalid or expired reset token');
  //   // }

  //   const payload = await TokenService.verifyEmailToken(verificationToken);
  //   if (!payload || !payload.email) {
  //     throw new BadRequest('Invalid or expired reset token');
  //   }

  //   const user = await this.findUserByEmail(payload.email);
  //   if (!user) {
  //     throw new BadRequest('Invalid or expired reset token');
  //   }

  //   // Add the old password to history before updating
  //   user.passwordHistory = user.passwordHistory ?? [];
  //   const isPasswordUsedBefore = user.passwordHistory.some((entry) =>
  //     bcrypt.compareSync(newPassword, entry.password)
  //   );

  //   if (isPasswordUsedBefore) {
  //     throw new BadRequest(
  //       'This password has been used before. Please choose a new password.'
  //     );
  //   }

  //   user.passwordHistory.push({
  //     password: user.password,
  //     changedAt: new Date(),
  //   });

  //   const PASSWORD_HISTORY_LIMIT = 5;
  //   if (user.passwordHistory.length > PASSWORD_HISTORY_LIMIT) {
  //     user.passwordHistory = user.passwordHistory.slice(
  //       -PASSWORD_HISTORY_LIMIT
  //     );
  //   }

  //   user.password = newPassword;
  //   user.emailVerificationOTP = null;
  //   user.failedLoginAttempts = 0;
  //   user.isLocked = false;
  //   await this.userRepository.save(user);

  //   const emailOptions = PasswordResetEmail(user);
  //   await EmailQueueService.addEmailToQueue(emailOptions);
  // }

  // public async login(credentials: LoginCredentials): Promise<loginResponse> {
  //   const user = await this.findUserByEmail(credentials.email);
  //   if (!user) {
  //     throw new ResourceNotFound('Invalid email or password');
  //   }

  //   if (!user.isEmailVerified) {
  //     throw new Forbidden('Verify your email before sign in.');
  //   }

  //   const isValid = await user.comparePassword(credentials.password);
  //   if (!isValid) {
  //     user.failedLoginAttempts += 1;
  //     if (user.failedLoginAttempts >= 3) {
  //       user.isLocked = true;
  //       await this.userRepository.save(user);
  //       throw new Forbidden(
  //         'Your account has been locked due to multiple failed login attempts. Please reset your password.'
  //       );
  //     }
  //     await this.userRepository.save(user);
  //     throw new Unauthorized('Invalid email or password');
  //   }

  //   user.failedLoginAttempts = 0;
  //   await this.userRepository.save(user);

  //   const requestedRole = credentials.role || 'user';
  //   if (!user.role.includes(requestedRole)) {
  //     throw new Forbidden(
  //       `You do not have permission to sign in as ${requestedRole}`
  //     );
  //   }

  //   const token = TokenService.createAuthToken({
  //     userId: user.id.toString(),
  //     role: user.role,
  //   });

  //   return {
  //     user: this.sanitizeUser(user),
  //     token,
  //   };
  // }
}
