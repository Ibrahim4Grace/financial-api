import { MigrationInterface, QueryRunner } from "typeorm";

export class Init1738663641724 implements MigrationInterface {
    name = 'Init1738663641724'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "user" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "name" character varying(255) NOT NULL, "email" character varying(100) NOT NULL, "password" character varying(255) NOT NULL, "age" integer NOT NULL, "isEmailVerified" boolean NOT NULL DEFAULT false, "emailVerificationOTP" json, "passwordHistory" json NOT NULL DEFAULT '[]', "failedLoginAttempts" integer NOT NULL DEFAULT '0', "isLocked" boolean NOT NULL DEFAULT false, "role" text NOT NULL DEFAULT 'admin', "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_cace4a159ff9f2512dd42373760" PRIMARY KEY ("id"))`);
        await queryRunner.query(`CREATE TABLE "admin" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "name" character varying(255) NOT NULL, "email" character varying(100) NOT NULL, "password" character varying(255) NOT NULL, "age" integer NOT NULL, "isEmailVerified" boolean NOT NULL DEFAULT false, "emailVerificationOTP" json, "passwordHistory" json NOT NULL DEFAULT '[]', "failedLoginAttempts" integer NOT NULL DEFAULT '0', "isLocked" boolean NOT NULL DEFAULT false, "role" text NOT NULL DEFAULT 'user', "createdAt" TIMESTAMP NOT NULL DEFAULT now(), "updatedAt" TIMESTAMP NOT NULL DEFAULT now(), CONSTRAINT "PK_e032310bcef831fb83101899b10" PRIMARY KEY ("id"))`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP TABLE "admin"`);
        await queryRunner.query(`DROP TABLE "user"`);
    }

}
