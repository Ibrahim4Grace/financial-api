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

@Entity()
export class User extends BaseEntity {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 100 })
  email: string;

  @Column({ type: 'varchar', length: 255 })
  password!: string;

  @Column({ default: false })
  isEmailVerified: boolean;

  @Column({ type: 'json', nullable: true })
  emailVerificationOTP: {
    otp: string;
    verificationToken: string;
    expiresAt: Date;
  } | null;

  @Column({ type: 'json', default: [] })
  passwordHistory: Array<{
    password: string;
    changedAt: Date;
  }>;

  @Column({ default: 0 })
  failedLoginAttempts: number;

  @Column({ default: false })
  isLocked: boolean;

  @Column('text', { default: 'admin' })
  role: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    if (this.password && this.password.length > 0) {
      this.password = await bcrypt.hash(this.password, 10);
    }
  }

  async comparePassword(candidatePassword: string): Promise<boolean> {
    return bcrypt.compare(candidatePassword, this.password);
  }
}
