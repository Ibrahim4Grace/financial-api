import {
  BaseEntity,
  BeforeInsert,
  BeforeUpdate,
  Entity,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
} from 'typeorm';
import { validateOrReject } from 'class-validator';

@Entity()
export class ExtendedBaseEntity extends BaseEntity {
  @BeforeInsert()
  async validateOnInsert() {
    await validateOrReject(this);
  }

  @BeforeUpdate()
  async validateOnUpdate() {
    await validateOrReject(this, { skipMissingProperties: true });
  }

  @PrimaryGeneratedColumn('uuid')
  id!: string;

  @CreateDateColumn({ name: 'created_at' })
  created_at!: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updated_at!: Date;

  @DeleteDateColumn({ nullable: true })
  deleted_at!: Date;
}

export default ExtendedBaseEntity;
