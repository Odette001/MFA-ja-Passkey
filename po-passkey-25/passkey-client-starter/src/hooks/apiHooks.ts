import { User } from '@sharedTypes/DBTypes';
import fetchData from '@/lib/fetchData';
import { UserResponse } from '@sharedTypes/MessageTypes';
//import { startAuthentication } from '@simplewebauthn/browser';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
import {PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON} 
from '@simplewebauthn/types';
// add imports for WebAuthn functions

const useUser = () => {
  // implement network functions for auth server user endpoints
  const getUserByToken = async (token: string) => {
    const options = {
      headers: {
        Authorization: 'Bearer ' + token,
      },
    };
    return await fetchData<UserResponse>(
      import.meta.env.VITE_AUTH_API + '/users/token/',
      options,
    );
  };

  const getUsernameAvailable = async (username: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + '/users/username/' + username,
    );
  };

  const getEmailAvailable = async (email: string) => {
    return await fetchData<{ available: boolean }>(
      import.meta.env.VITE_AUTH_API + '/users/email/' + email,
    );
  };

  return { getUserByToken, getUsernameAvailable, getEmailAvailable };
};

// Define usePasskey hook
const usePasskey = () => {
  const postUser = async (
    user: Pick<User, 'username' | 'password' | 'email'>,
  ) => {
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(user),
    };

    // TODO: Fetch setup response
    const registrationResponse = await fetchData<{
      email: string;
      options: PublicKeyCredentialCreationOptionsJSON;
    }>(import.meta.env.VITE_PASSKEY_API + '/auth/setup', options);

    const attResp = await startRegistration(registrationResponse.options as PublicKeyCredentialCreationOptionsJSON);

    const data = {
      email: registrationResponse.email,
      registrationOptions: attResp,
    };

    const verifyOptions = {
      ...options,
      body: JSON.stringify(data),
    };

    return await fetchData(
      import.meta.env.VITE_PASSKEY_API + '/auth/verify',
      verifyOptions,
    );
  };

  // TODO: Define postLogin function
  const postLogin = async (email : string) => {
    // TODO: Fetch login setup options
    const loginOptions = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({email}),
    };
    const authenticationResponse = await fetchData<PublicKeyCredentialRequestOptionsJSON>(
      import.meta.env.VITE_PASSKEY_API + '/auth/login-setup',
      loginOptions,
    );
    // Start authentication process
    const attResp = await startAuthentication(authenticationResponse);

    // Fetch and return login verification response
    const verifyOptions = {
      ...loginOptions,
      body: JSON.stringify({
        email,
        authResponse: attResp,
      }),
    };
    return await fetchData(
      import.meta.env.VITE_PASSKEY_API + '/auth/login-verify',
      verifyOptions,
    );
  };

  // TODO: Return postUser and postLogin functions
  return { postUser, postLogin };
};

export { useUser, usePasskey };
