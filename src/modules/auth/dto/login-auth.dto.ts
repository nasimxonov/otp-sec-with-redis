import { IsPhoneNumber, IsString } from 'class-validator';

export class sendCodeLoginDto {
  @IsString()
  phone: string;
  @IsString()
  password: string;
}

export class verifyCodeLoginDto {
  @IsString()
  code: string;
  @IsString()
  phone: string;
}
