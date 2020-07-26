import { User } from 'src/auth/user.entity';
import { GetUser } from './get-user.decorator';
import {
  Controller,
  Post,
  Body,
  ValidationPipe,
  Get,
  UseGuards,
  Request,
  Response,
  Patch,
} from '@nestjs/common';
import {
  AuthCredentialsDto,
  StrongPasswordDto,
} from './dto/auth-credentials.dto';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  signUp(
    @Body(ValidationPipe) authCredentialsDto: AuthCredentialsDto,
  ): Promise<void> {
    return this.authService.signUp(authCredentialsDto);
  }

  @Post('/signin')
  signIn(
    @Body(ValidationPipe) authCredentialsDto: AuthCredentialsDto,
  ): Promise<{ accessToken: string }> {
    return this.authService.signIn(authCredentialsDto);
  }

  @Get('/profile')
  @UseGuards(AuthGuard('jwt'))
  async profile(
    @Request() req,
    @Response() res,
    @GetUser() user: User,
  ): Promise<{ user: object }> {
    const result = await this.authService.getUserProfile(user.id);
    const { username, email } = result;

    return res.status(200).send({ user: { username, email } });
  }

  @Patch('/update')
  @UseGuards(AuthGuard('jwt'))
  async update(
    @Request() req,
    @Response() res,
    @GetUser() user: User,
    @Body(ValidationPipe) strongPassword: StrongPasswordDto,
  ): Promise<any> {
    try {
      const { success } = await this.authService.changePassword(user.id);
      res.status(200).send(success);
    } catch (err) {
      console.log('err: ', err);
    }
  }
}
