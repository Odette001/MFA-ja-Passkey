import { Button } from '@/components/ui/button';
import { CardContent, CardFooter, CardHeader } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Input } from '@/components/ui/input';
import { usePasskey, useUser } from '@/hooks/apiHooks';
import { useState } from 'react';
import { useForm } from '@/hooks/formHooks';
import { useUserContext } from '@/hooks/contextHooks';

const RegisterForm = (props: { switchForm: () => void }) => {
  const { postUser } = usePasskey();
  const [usernameAvailable, setUsernameAvailable] = useState<boolean>(true);
  const [emailAvailable, setEmailAvailable] = useState<boolean>(true);
  const [usernameValid, setUsernameValid] = useState<boolean>(true);
  const { handleRegister } = useUserContext();

  const initValues = { username: '', password: '', email: '' };

  const doRegister = async () => {
    try {
      if (!usernameAvailable || !emailAvailable || !usernameValid) {
        return;
      }
      const registerResponse = await postUser(inputs);
      if (
        registerResponse &&
        typeof registerResponse === 'object' &&
        'user' in registerResponse
      ) {
        handleRegister((registerResponse as { user: any }).user);
        props.switchForm();
      } else {
        throw new Error('Invalid register response');
      }
    } catch (error) {
      console.log((error as Error).message);
    }
  };

  const { handleSubmit, handleInputChange, inputs } = useForm(
    doRegister,
    initValues,
  );
  const { getUsernameAvailable, getEmailAvailable } = useUser();

  const handleUsernameBlur = async (
    event: React.SyntheticEvent<HTMLInputElement>,
  ) => {
    const username = event.currentTarget.value;
    // Check if username contains only allowed characters
    const isValid = /^[a-zA-Z0-9_-]+$/.test(username) && username.length >= 3 && username.length <= 50;
    setUsernameValid(isValid);
    
    if (isValid) {
      const result = await getUsernameAvailable(username);
      setUsernameAvailable(result.available);
    } else {
      setUsernameAvailable(false);
    }
  };

  const handleEmailBlur = async () => {
    const result = await getEmailAvailable(inputs.email); // voidaan käyttää myös inputs objektia
    setEmailAvailable(result.available);
  };

  console.log(usernameAvailable, emailAvailable);
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
            {!usernameValid && (
              <p className="text-red-500">Username can only contain letters, numbers, underscores, and dashes (3-50 characters)</p>
            )}
            {!usernameAvailable && usernameValid && (
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
