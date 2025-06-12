import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export default class PrismaService implements OnModuleInit, OnModuleDestroy {
  public prisma: PrismaClient;
  constructor() {
    this.prisma = new PrismaClient();
  }
  async onModuleInit() {
    try {
      await this.prisma.$connect();
      console.log('Prisma connected');
    } catch (error) {
      console.error(error);
    }
  }
  async onModuleDestroy() {
    await this.prisma.$disconnect();
    process.exit(1);
  }
}
