import { Button } from '@/components/ui/button';
import { CardContent, CardFooter, CardHeader } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { useState } from 'react';
import { useForm } from '@/hooks/formHooks';
import Setup2FA from './Setup2FA';
import { use2FA, useUser } from '@/hooks/apiHooks';

const RegisterForm = (props: { switchForm: () => void }) => {
  const [usernameAvailable, setUsernameAvailable] = useState<boolean>(true);
  const [emailAvailable, setEmailAvailable] = useState<boolean>(true);
  const [qrCodeUrl, setQrCodeUrl] = useState<string>('');

  const initValues = { username: '', password: '', email: '' };

  const doRegister = async () => {
    try {
      if (!usernameAvailable || !emailAvailable) {
        return;
      }
      const registerResponse = await postUser(inputs);
      setQrCodeUrl(registerResponse.qrCodeUrl);
    } catch (error) {
      console.log((error as Error).message);
    }
  };

  const { handleSubmit, handleInputChange, inputs } = useForm(
    doRegister,
    initValues,
  );

  const { getUsernameAvailable, getEmailAvailable } = useUser();
  const { postUser } = use2FA();

  const handleUsernameBlur = async (
    event: React.SyntheticEvent<HTMLInputElement>,
  ) => {
    const result = await getUsernameAvailable(event.currentTarget.value);
    setUsernameAvailable(result.available);
  };

  const handleEmailBlur = async () => {
    const result = await getEmailAvailable(inputs.email); // voidaan käyttää myös inputs objektia
    setEmailAvailable(result.available);
  };

  console.log(usernameAvailable, emailAvailable);
  
  // Show Setup2FA only after registration is successful and we have a QR code
  if (qrCodeUrl) {
    return <Setup2FA qrCodeUrl={qrCodeUrl} switchForm={props.switchForm} />;
  }

  return (
    <>
      <form onSubmit={handleSubmit}>
        <CardHeader className="text-center">
          <h2 className="text-2xl font-bold">Register</h2>
        </CardHeader>
        <CardContent className="space-y-4 px-6 py-8">
          <div className="space-y-2">
            <Label htmlFor="username">Full Name</Label>
            <Input
              id="username"
              name="username"
              type="text"
              placeholder="Username"
              required
              onChange={handleInputChange}
              onBlur={handleUsernameBlur}
            />
            {!usernameAvailable && (
              <p className="text-red-500">Username not available</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              name="email"
              type="email"
              placeholder="m@example.com"
              required
              onChange={handleInputChange}
              onBlur={handleEmailBlur}
            />
            {!emailAvailable && (
              <p className="text-red-500">Email not available</p>
            )}
          </div>
          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              onChange={handleInputChange}
              id="password"
              name="password"
              type="password"
              required
            />
          </div>
        </CardContent>
        <CardFooter className="px-6 pb-6">
          <div className="w-full flex justify-center">
            <Button>Register</Button>
          </div>
        </CardFooter>
      </form>
    </>
  );
};

export default RegisterForm;
