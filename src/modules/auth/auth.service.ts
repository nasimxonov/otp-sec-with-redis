import {
  BadRequestException,
  ConflictException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import PrismaService from 'src/core/database/prisma.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import VerifyOtpDto from './dto/verify.otp.dto';
import OtpService from './otp.service';
import bcrypt from 'bcrypt';
import { sendCodeLoginDto, verifyCodeLoginDto } from './dto/login-auth.dto';
@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private db: PrismaService,
    private otpService: OtpService,
  ) {}
  async sendOtpUser(createAuthDto: CreateAuthDto) {
    const findUser = await this.db.prisma.user.findFirst({
      where: {
        phone_number: createAuthDto.phone_number,
      },
    });
    if (findUser) throw new ConflictException('phone_number already exists');
    const phoneNumber = createAuthDto.phone_number;
    const res = await this.otpService.sendOtp(phoneNumber);
    if (!res) throw new InternalServerErrorException('Server error');
    return {
      message: 'code sended',
    };
  }
  async verifyOtp(data: VerifyOtpDto) {
    const key = `user:${data.phone_number}`;
    const sessionToken = await this.otpService.verifyOtpSendedUser(
      key,
      data.code,
      data.phone_number,
    );
    return {
      message: 'success',
      statusCode: 200,
      session_token: sessionToken,
    };
  }

  async register(createAuthDto: CreateAuthDto) {
    const findUser = await this.db.prisma.user.findFirst({
      where: {
        phone_number: createAuthDto.phone_number,
      },
    });
    if (findUser) throw new ConflictException('phone_number already exists');
    const key = `session_token:${createAuthDto.phone_number}`;
    await this.otpService.checkSessionTokenUser(
      key,
      createAuthDto.session_token,
    );
    const hashedPassword = await bcrypt.hash(createAuthDto.password, 12);
    const user = await this.db.prisma.user.create({
      data: {
        phone_number: createAuthDto.phone_number,
        password: hashedPassword,
      },
    });
    const token = this.jwtService.sign({ user_id: user.id });
    await this.otpService.delSessionTokenUser(key);
    return token;
  }
  async sendCodeLogin(data: sendCodeLoginDto) {
    try {
      const findUser = await this.db.prisma.user.findUnique({
        where: { phone_number: data.phone },
      });
      if (!findUser) throw new ConflictException('User not found');
      const checkPassword = await bcrypt.compare(
        data.password,
        findUser.password,
      );
      if (!checkPassword) {
        throw new UnauthorizedException('Incorrect password');
      }
      const res = await this.otpService.sendOtp(data.phone);
      if (!res) throw new InternalServerErrorException('Server error');
      return {
        message: 'Code sended',
      };
    } catch (error) {
      throw new InternalServerErrorException('Internal server error');
    }
  }

  async verifyCodeLogin(data: verifyCodeLoginDto) {
    try {
      const existedUser = await this.db.prisma.user.findUnique({
        where: { phone_number: data.phone },
      });
      if (!existedUser) throw new BadRequestException('User not found');
      const key = `user:${data.phone}`;
      await this.otpService.verifyOtpSendedUser(key, data.code, data.phone);
      const token = await this.jwtService.signAsync({ userId: existedUser.id });
      await this.otpService.delSessionTokenUser(key);
      return token;
    } catch (error) {
      throw new InternalServerErrorException('Internal server error');
    }
  }
}
