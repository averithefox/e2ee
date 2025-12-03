import '~/index.css';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Route, Switch } from 'wouter';
import NotFoundView from './views/not-found';

const queryClient = new QueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Switch>
        <Route component={NotFoundView} />
      </Switch>
    </QueryClientProvider>
  );
}

export default App;
