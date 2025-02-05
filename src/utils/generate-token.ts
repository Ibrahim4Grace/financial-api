import { TokenService } from '../utils';
import otpGenerator from 'otp-generator';
import bcrypt from 'bcryptjs';

export const generateOTP = async () => {
  const otp = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  const hashedOTP = await bcrypt.hash(otp, 10);
  return { otp, hashedOTP };
};

export async function generateEmailVerificationOTP(
  userId: string,
  email: string
): Promise<{
  otp: string;
  verificationToken: string;
}> {
  const { otp, hashedOTP } = await generateOTP();

  const verificationToken = TokenService.createEmailVerificationToken({
    userId,
    email,
  });

  this.emailVerificationOTP = {
    otp: hashedOTP,
    expiresAt: new Date(Date.now() + Number(process.env.OTP_EXPIRY)),
    verificationToken,
  };

  return { otp, verificationToken };
}
