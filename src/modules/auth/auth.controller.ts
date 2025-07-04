import { Body, Controller, HttpException, HttpStatus, Post, Res } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import VerifyOtpDto from './dto/verify.otp.dto';
import { sendCodeLoginDto, verifyCodeLoginDto } from './dto/login-auth.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}
  @Post('send-otp')
  async sendOtpUser(@Body() createAuthDto: CreateAuthDto) {
    const response = await this.authService.sendOtpUser(createAuthDto);
    return response;
  }
  @Post('verify-otp')
  async verifyOtp(@Body() data: VerifyOtpDto) {
    return await this.authService.verifyOtp(data);
  }
  @Post('register')
  async register(
    @Body() createAuthDto: CreateAuthDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const token = await this.authService.register(createAuthDto);
    res.cookie('token', token, {
      maxAge: 1.1 * 3600 * 1000,
      httpOnly: true,
    });
    return { token };
  }

  @Post('send-code-login')
  async sendCodeLogin(@Body() data: sendCodeLoginDto) {
    try {
      const response = await this.authService.sendCodeLogin(data);
      return response;
    } catch (error) {
      throw new HttpException(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }

  @Post('verify-login')
  async verifyLogin(
    @Body() data: verifyCodeLoginDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    try {
      const token = await this.authService.verifyCodeLogin(data);
      res.cookie('token', token, {
        httpOnly: true,
        maxAge: 1.1 * 3600 * 1000,
      });
      return { token };
    } catch (error) {
      throw new HttpException(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
