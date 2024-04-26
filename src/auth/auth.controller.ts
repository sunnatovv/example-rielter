import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { Response } from 'express';
import { AccessTokenGuard } from '../common/guards';
import { LoginAuthDto } from './dto/login-auth.dto.';
import { CookieGetter } from '../decorators/cookie_getter.decorator';
import { Public } from '../common/decorators';


  @UseGuards(AccessTokenGuard)
  @Controller('auth')
  export class AuthController {
    constructor(private readonly authService: AuthService) {}

    // @UseGuards(AccessTokenGuard)
    @Public()
    @Post('signup')
    async signup(
      @Body() createAuthDto: CreateAuthDto,
      @Res({ passthrough: true }) res: Response,
    ) {
      return this.authService.signup(createAuthDto, res);
    }
    @Public()
    @Post('signin')
    async login(
      @Body() loginAuthDto: LoginAuthDto,
      @Res({ passthrough: true }) res: Response,
    ): Promise<any> {
      return this.authService.signin(loginAuthDto, res);
    }
    @Post(':id/refresh')
    async refresh(
      @Param('id') id: number,
      @CookieGetter('refresh_token') refreshToken: string,
      @Res({ passthrough: true }) res: Response,
    ) {
      return this.authService.refreshToken(+id, refreshToken, res);
    }

    @Post()
    create(@Body() createAuthDto: CreateAuthDto) {
      return this.authService.create(createAuthDto);
    }

    @Get()
    findAll() {
      return this.authService.findAll();
    }

    @Get(':id')
    findOne(@Param('id') id: string) {
      return this.authService.findOne(+id);
    }

    @Patch(':id')
    update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
      return this.authService.update(+id, updateAuthDto);
    }

    @Delete(':id')
    remove(@Param('id') id: string) {
      return this.authService.remove(+id);
    }
  }
