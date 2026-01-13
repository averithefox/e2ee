import '~/index.css';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Route, Switch } from 'wouter';
import { Toaster } from '~/components/ui/sonner';
import HomeView from './views/home.view';
import NotFoundView from './views/not-found.view';
import { RegisterView } from './views/register.view';

const queryClient = new QueryClient();

export function App() {
  return (
    <>
      <QueryClientProvider client={queryClient}>
        <Switch>
          <Route path="/" component={HomeView} />
          <Route path="/register" component={RegisterView} />
          <Route component={NotFoundView} />
        </Switch>
      </QueryClientProvider>
      <Toaster position="top-right" swipeDirections={['right']} />
    </>
  );
}

export default App;
