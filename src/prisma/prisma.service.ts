import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
    constructor(){
        super({
            datasources:{
                db:{
                    url: "postgresql://postgres:root@localhost:5432/prisma-passport?schema=public"
                },
            },
        })

    }
  async onModuleInit() {
    await this.$disconnect();
  }
  async onModuleDestroy() {
    await this.$disconnect();
  }
}
