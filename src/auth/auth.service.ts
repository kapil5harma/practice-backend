// import { UserRO } from './../user/user.interface';
import { User } from './user.entity';
import {
  Injectable,
  UnauthorizedException,
  Logger,
  HttpException,
  ConflictException,
  InternalServerErrorException,
} from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { UserRepository } from './user.repository';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';
import { JwtPayload } from './jwt-payload.interface';

@Injectable()
export class AuthService {
  private logger = new Logger('AuthService');

  constructor(
    @InjectRepository(UserRepository)
    private userRepository: UserRepository,
    private jwtService: JwtService,
  ) {}

  async signUp(authCredentialsDto: AuthCredentialsDto): Promise<void> {
    return this.userRepository.signUp(authCredentialsDto);
  }

  async signIn(
    authCredentialsDto: AuthCredentialsDto,
  ): Promise<{ accessToken: string }> {
    const username = await this.userRepository.validateUserPassword(
      authCredentialsDto,
    );

    if (!username) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload: JwtPayload = { username };
    const accessToken = await this.jwtService.sign(payload);
    this.logger.debug(
      `Generated JWT Token with payload ${JSON.stringify(payload)}`,
    );

    return { accessToken };
  }

  async getUserProfile(
    userId: any,
  ): Promise<{ username: string; email: string }> {
    const user = await this.userRepository.findOne(userId);

    if (!user) {
      const errors = { User: ' not found' };
      throw new HttpException({ errors }, 401);
    }

    // return { user };
    return { username: user.username, email: user.email };
  }

  async changePassword(userId: any): Promise<any> {
    const user = await this.userRepository.findOne(userId);

    if (!user) {
      const errors = { User: ' not found' };
      throw new HttpException({ errors }, 401);
    }

    user.salt = await bcrypt.genSalt();
    user.password = await this.userRepository.hashPassword(
      user.password,
      user.salt,
    );

    try {
      await user.save();
      return { success: true };
    } catch (error) {
      console.log('error: ', error);
      throw new InternalServerErrorException();
    }
  }
}
