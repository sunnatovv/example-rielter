import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import * as cookieParser from 'cookie-parser';

const bootstrap = async()=> {
  try {
    const app = await NestFactory.create(AppModule);
    const PORT = process.env.PORT;
    app.use(cookieParser());
    app.useGlobalPipes(new ValidationPipe());
    await app.listen(PORT || 3030, () => {
      console.log(`server started at ${PORT}-PORT`);
    });
  } catch (error) {
    console.log(error);
  }
}
bootstrap();
