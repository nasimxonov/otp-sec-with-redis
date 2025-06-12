import { Global, Module } from '@nestjs/common';
import RedisService from './redis.service';
import PrismaService from './prisma.service';
@Global()
@Module({
  providers: [RedisService, PrismaService],
  exports: [RedisService, PrismaService],
})
export class DatabaseModule {}
