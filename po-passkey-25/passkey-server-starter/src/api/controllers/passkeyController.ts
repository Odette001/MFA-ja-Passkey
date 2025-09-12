import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import {User} from '@sharedTypes/DBTypes';
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import fetchData from '../../utils/fetchData';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {AuthDevice, Challenge, PasskeyUserGet, PasskeyUserPost} from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';
import {
  RegistrationResponseJSON, 
  AuthenticationResponseJSON, 
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON
} from '@simplewebauthn/types';
import authenticatorDeviceModel from '../models/authenticatorDeviceModel';
import { Types } from 'mongoose';
import { GenerateAuthenticationOptionsOpts } from '@simplewebauthn/server';
import { decodeCredentialPublicKey } from '@simplewebauthn/server/helpers';
import jwt from 'jsonwebtoken';
// check environment variables
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

const {NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME} = process.env;

console.log(NODE_ENV, JWT_SECRET);

// Registration handler
const setupPasskey = async (
  req: Request<{}, {}, User>,
  res: Response<{
    email: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>,
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
    const userResponse = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users',
      options,
    );

    if (!userResponse) {
      next(new CustomError('User not created', 400));
      return;
    }

    const regOptions = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: userResponse.user.username,
      attestationType: 'none',
      timeout: 60000,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'discouraged',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    // console.log(regOptions);

    const challenge: Challenge = {
      challenge: regOptions.challenge,
      email: userResponse.user.email,
    };

    await challengeModel.create(challenge);

    const passkeyUser: PasskeyUserPost = {
      email: userResponse.user.email,
      userId: userResponse.user.user_id,
      devices: [],
    };

    await passkeyUserModel.create(passkeyUser);

    res.json({
      email: userResponse.user.email,
      options: regOptions,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Registration verification handler
const verifyPasskey = async (
  req: Request<
    {},
    {},
    {
      email: string;
      registrationOptions: RegistrationResponseJSON;
    }
  >,
  res: Response<UserResponse>,
  next: NextFunction,
) => {
  try {
    const expectedChallenge = await challengeModel.findOne({
      email: req.body.email,
    });

    if (!expectedChallenge) {
      next(new CustomError('challenge not found', 404));
      return;
    }

    //  Verify registration response
    const opts: VerifyRegistrationResponseOpts = {
      response: req.body.registrationOptions,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development'
          ? `http://${RP_ID}:5173`
          : `https://${RP_ID}`,
      expectedRPID: RP_ID,
      requireUserVerification: false,
    };
    const verification = await verifyRegistrationResponse(opts);

    const {verified, registrationInfo} = verification;

    console.log('Verification result:', { verified, registrationInfo: !!registrationInfo });

    if (!verified || !registrationInfo) {
      console.log('Verification failed:', { verified, hasRegistrationInfo: !!registrationInfo });
      next(new CustomError('Verification failed', 403));
      return;
    }
    //  Check if device is already registered
    const {credentialPublicKey, credentialID, counter} = registrationInfo;
    const existingDevice = await authenticatorDeviceModel.findOne({
      credentialID,
    });
    if (existingDevice) {
      next(new CustomError('Device already registred', 400));
      return;
    }

    //Save new authenticator to AuthenticatorDevice collection
    console.log('Creating device with transports:', req.body.registrationOptions.response?.transports);
    const newDevice =  new authenticatorDeviceModel({
      email: req.body.email,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      credentialID,
      counter,
      transports: req.body.registrationOptions.response?.transports || [],
    });
    const newDeviceResult = await newDevice.save();
    console.log('Device saved with ID:', newDeviceResult._id);

    // Update user devices array in DB (Vähää erilainen kuin tavallienen updataus tapaa)
    const user = await passkeyUserModel.findOne({ email: req.body.email });
    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }
    user.devices.push(newDeviceResult._id as Types.ObjectId);
    await user.save();
    console.log('User updated with device. Total devices:', user.devices.length);

    // TODO: Clear challenge from DB after successful registration
    await challengeModel.findOneAndDelete({ email: req.body.email });
    // TODO: Retrieve and send user details from AUTH API
    const userResponse = await fetchData<UserResponse>(AUTH_URL + '/api/v1/users/' + user.userId);
    res.json(userResponse);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request<{}, {}, { email: string }>,
  res: Response<PublicKeyCredentialRequestOptionsJSON>,
  next: NextFunction,
) => {
  try {
    // TODO: Retrieve user and associated devices from DB
    const user = (await passkeyUserModel
      .findOne({ email: req.body.email })
      .populate('devices')) as unknown as PasskeyUserGet;

      if (!user) {
        next(new CustomError('User not found', 404));
        return;
      }

      if (!user.devices || user.devices.length === 0) {
        next(new CustomError('No authenticator devices found for user', 404));
        return;
      }

    // TODO: Generate authentication options
    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      rpID: RP_ID,
      allowCredentials: user.devices.map((device) => ({
        id: device.credentialID,
        type: 'public-key',
        transports: device.transports,
      })),
      userVerification: 'discouraged',
    };
    const options = await generateAuthenticationOptions(opts);
    // TODO: Save challenge to DB
    await challengeModel.create({ email: req.body.email,
      challenge: options.challenge,
    });
    // TODO: Send options in response
    res.json(options);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request<{}, {}, { email: string; authResponse: AuthenticationResponseJSON }>,
  res: Response,
  next: NextFunction,
) => {
  try {
    //  Retrieve expected challenge from DB
    const challenge = await challengeModel.findOne({ email: req.body.email });
    if (!challenge) {
      next(new CustomError('Challenge not found', 404));
      return;
    }
    //  Verify authentication response
    const user = (await passkeyUserModel.findOne({email: req.body.email}).populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next( new CustomError('User not found', 404));
      return;
    }

    if (!user.devices || user.devices.length === 0) {
      next(new CustomError('No authenticator devices found for user', 404));
      return;
    }

    const opts = {
      expectedRPID: RP_ID,
      response: req.body.authResponse,
      expectedChallenge: challenge.challenge,
      expectedOrigin: NODE_ENV === 'development' ? `http://${RP_ID}:5173` : `https://${RP_ID}`,
      authenticator: {
        credentialPublicKey: Buffer.from(user.devices[0].credentialPublicKey),
        credentialID: user.devices[0].credentialID,
        counter: user.devices[0].counter,
        transports: user.devices[0].transports,
      },
      requireUserVerification: false,
    };
    const verification = await verifyAuthenticationResponse(opts);

    const {verified, authenticationInfo} = verification;
     // Update authenticator's counter

    if (verified){
      await authenticatorDeviceModel.findOneAndUpdate(
        { _id: user.devices[0]._id },
        {
          counter: authenticationInfo.newCounter,
        }
      );
    }

    if (!verified) {
      next(new CustomError('User verification required, but user could not be verified', 400));
      return;
    }
   
    // Clear challenge from DB after successful authentication
    await challengeModel.findOneAndDelete({ email: req.body.email });
    // Generate and send JWT token
    console.log('Fetching user details for userId:', user.userId);
    console.log('AUTH_URL:', AUTH_URL);
    console.log('Full URL:', AUTH_URL + '/api/v1/users/' + user.userId);
    
    let userResponse;
    try {
      userResponse = await fetchData<UserResponse>(
        AUTH_URL + '/api/v1/users/' + user.userId,
      );
      console.log('User response received:', !!userResponse);
    } catch (fetchError) {
      console.log('Fetch error:', (fetchError as Error).message);
      // Fallback: create a minimal user response
      userResponse = {
        message: 'User found',
        user: {
          user_id: user.userId,
          username: user.email.split('@')[0], // Extract username from email
          email: user.email,
          level_name: 'User' as const,
          created_at: new Date().toISOString()
        }
      };
      console.log('Using fallback user response');
    }

    if (!userResponse) {
      next(new CustomError('User not found', 404));
      return;
    }

    
    let userData;
    if (userResponse.user) {
      
      userData = userResponse.user;
    } else if ((userResponse as any).user_id) {
      
      userData = userResponse as any;
    } else {
      console.log('userResponse structure:', JSON.stringify(userResponse, null, 2));
      next(new CustomError('Invalid user response structure', 500));
      return;
    }
    const token = jwt.sign(
      {
        user_id: userData.user_id,
        level_name: userData.level_name,
      },
      JWT_SECRET as string,
    );
    const message: LoginResponse = {
      message: 'Logged in successfully',
      user: userData,
      token,
    };
    res.json(message);


  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Debugging endpoints to check database content
const getAllUsers = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    const users = await passkeyUserModel.find().populate('devices');
    res.json({ users, count: users.length });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

const getUserByEmail = async (
  req: Request<{email: string}>,
  res: Response,
  next: NextFunction,
) => {
  try {
    const user = await passkeyUserModel.findOne({ email: req.params.email }).populate('devices');
    if (!user) {
      res.json({ message: 'User not found', email: req.params.email });
      return;
    }
    res.json({ user, deviceCount: user.devices.length });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
  getAllUsers,
  getUserByEmail,
};
