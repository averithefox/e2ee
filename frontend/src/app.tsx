import '~/index.css';

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Route, Switch } from 'wouter';
import NotFoundView from './views/not-found.view';
import TestView from './views/test.view';

const queryClient = new QueryClient();

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Switch>
        {process.env.NODE_ENV !== 'production' && <Route path="/test" component={TestView} />}
        <Route component={NotFoundView} />
      </Switch>
    </QueryClientProvider>
  );
}

export default App;
