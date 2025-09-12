import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import {TokenContent, User, UserWithLevel} from '@sharedTypes/DBTypes';
import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import fetchData from '../../utils/fetchData';
import OTPAuth from 'otpauth';
import twoFAModel from '../models/twoFAModel';
import QRCode from 'qrcode';
import jwt from 'jsonwebtoken';

const setupTwoFA = async (
  req: Request<{}, {}, User>,
  res: Response<{qrCodeUrl: string}>,
  next: NextFunction,
) => {
  try {
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const userRespose = await fetchData<UserResponse>(
      process.env.AUTH_URL + '/api/v1/users',
      options,
    );

    console.log('userResponse', userRespose);

    const secret = new OTPAuth.Secret();

    const totp = new OTPAuth.TOTP({
      issuer: 'ElukkaAPI',
      label: userRespose.user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret,
    });

    await twoFAModel.create({
      email: userRespose.user.email,
      userId: userRespose.user.user_id,
      twoFactorEnabled: true,
      twoFactorSecret: secret.base32,
    });

    const imageUrl = await QRCode.toDataURL(totp.toString());

    res.json({qrCodeUrl: imageUrl});
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// TODO: Define verifyTwoFA function
const verifyTwoFA = async (
  req: Request<{}, {}, {email: string; code: string}>,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  const {email, code} = req.body;
  console.log(email, code);

  try {
    const twoFactorData = await twoFAModel.findOne({
      email: { $regex: new RegExp(`^${email}$`, 'i') }
    });
    if (!twoFactorData || !twoFactorData.twoFactorEnabled) {
      next(new CustomError('2FA not enabled', 400));
      return;
    }

    const totp = new OTPAuth.TOTP({
      issuer: 'ElukkaAPI',
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: OTPAuth.Secret.fromBase32(twoFactorData.twoFactorSecret),
    });

    const isValid = totp.validate({token: code, window: 1});

    if (isValid === null) {
      next(new CustomError('Verification code is not valid', 400));
      return;
    }

    const userResponse = await fetchData<UserWithLevel>(
      `${process.env.AUTH_URL}/api/v1/users/${twoFactorData.userId}`,
    );

    if (!userResponse) {
      next(new CustomError('User not found', 401));
      return;
    }
    // TODO: Create and return a JWT token
    const tokenContent: TokenContent = {
      user_id: userResponse.user_id,
      level_name: userResponse.level_name,
    };

    if (!process.env.JWT_SECRET) {
      next(new CustomError('JWT not set', 500));
      return;
    }

    const token = jwt.sign(tokenContent, process.env.JWT_SECRET);
    const loginResponse: LoginResponse = {
      user: userResponse,
      token,
      message: 'Login Success',
    };

    res.json(loginResponse);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {setupTwoFA, verifyTwoFA};
