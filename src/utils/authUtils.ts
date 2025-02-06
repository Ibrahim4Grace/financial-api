import { TokenService } from '../utils';
import otpGenerator from 'otp-generator';
import bcrypt from 'bcryptjs';
import { User } from '../entities';
import { AppDataSource } from '../data-source';

export class AuthUtils {
  private static async generateOTP() {
    const otp = otpGenerator.generate(6, {
      lowerCaseAlphabets: false,
      upperCaseAlphabets: false,
      specialChars: false,
    });
    const hashedOTP = await bcrypt.hash(otp, 10);
    return { otp, hashedOTP };
  }

  public static async generateEmailVerificationOTP(
    userId: string,
    email: string
  ): Promise<{
    otp: string;
    verificationToken: string;
  }> {
    const { otp, hashedOTP } = await this.generateOTP();
    const verificationToken = TokenService.createEmailVerificationToken({
      userId,
      email,
    });

    // Update user with OTP information
    const userRepo = AppDataSource.getRepository(User);
    await userRepo.update(
      { id: userId },
      {
        emailVerificationOTP: {
          otp: hashedOTP,
          verificationToken,
          expiresAt: new Date(Date.now() + Number(process.env.OTP_EXPIRY)),
        },
      }
    );

    return { otp, verificationToken };
  }
}
