import * as bcrypt from 'bcrypt';
import {
  Entity,
  BeforeInsert,
  BeforeUpdate,
  UpdateDateColumn,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  Column,
  BaseEntity,
} from 'typeorm';

@Entity('users')
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ nullable: false })
  name: string;

  @Column({ nullable: false })
  email: string;

  @Column({ nullable: false })
  password!: string;

  @Column({ default: false })
  isEmailVerified: boolean;

  @Column({ type: 'jsonb', nullable: true })
  emailVerificationOTP: {
    otp: string;
    verificationToken: string;
    expiresAt: Date;
  } | null;

  @Column({ type: 'jsonb', default: [] })
  passwordHistory: Array<{
    password: string;
    changedAt: Date;
  }>;

  @Column({ default: 0 })
  failedLoginAttempts: number;

  @Column({ default: false })
  isLocked: boolean;

  @Column('text', { default: 'user' })
  role: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
