import '~/index.css';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Route, Switch } from 'wouter';
import HomeView from './views/home.view';
import NotFoundView from './views/not-found.view';
import { RegisterView } from './views/register.view';

const queryClient = new QueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Switch>
        <Route path="/" component={HomeView} />
        <Route path="/register" component={RegisterView} />
        <Route component={NotFoundView} />
      </Switch>
    </QueryClientProvider>
  );
}

export default App;
