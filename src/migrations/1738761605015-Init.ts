import { MigrationInterface, QueryRunner } from "typeorm";

export class Init1738761605015 implements MigrationInterface {
    name = 'Init1738761605015'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "user" DROP COLUMN "age"`);
        await queryRunner.query(`ALTER TABLE "admin" DROP COLUMN "age"`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "admin" ADD "age" integer NOT NULL`);
        await queryRunner.query(`ALTER TABLE "user" ADD "age" integer NOT NULL`);
    }

}
