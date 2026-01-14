import { useRef, useState, type FormEvent } from 'react';
import { toast } from 'sonner';
import { useLocation } from 'wouter';
import { Button } from '~/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '~/components/ui/card';
import { Input } from '~/components/ui/input';
import { Label } from '~/components/ui/label';
import { registerIdentity } from '~/lib/api';
import { validateHandle } from '~/lib/utils';

export function RegisterView() {
  const [, navigate] = useLocation();
  const [validationError, setValidationError] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement>(null!);

  function handleInputChange(e: React.ChangeEvent<HTMLInputElement>) {
    const value = e.target.value.trim();
    setValidationError(value ? validateHandle(value) : null);
  }

  async function handleRegister(e: FormEvent) {
    e.preventDefault();

    const handle = inputRef.current.value.trim();
    const error = validateHandle(handle);
    if (error) {
      setValidationError(error);
      inputRef.current.focus();
      return;
    }

    toast.promise(async () => await registerIdentity(handle), {
      loading: 'Registering...',
      success: () => {
        navigate('/');
        return `Identity ${handle} registered successfully`;
      },
      error: data => data.message
    });
  }

  return (
    <main className="bg-background text-foreground flex min-h-screen w-full items-center justify-center">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Register</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleRegister}>
            <div className="flex flex-col gap-2">
              <div className="grid gap-2">
                <Label htmlFor="handle">Handle</Label>
                <Input
                  ref={inputRef}
                  id="handle"
                  type="text"
                  required
                  autoFocus
                  onChange={handleInputChange}
                  placeholder="your_handle"
                />
                {validationError && (
                  <p className="text-destructive text-xs">{validationError}</p>
                )}
                <p className="text-muted-foreground text-xs">
                  3-32 characters, lowercase letters, numbers, and underscores only
                </p>
              </div>
              <Button type="submit" className="w-full">
                Register
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}

export default RegisterView;
