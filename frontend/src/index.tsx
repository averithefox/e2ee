import { createRoot } from 'react-dom/client';
import App from '~/app';

function start() {
  const root = createRoot(document.getElementById('root')!);
  root.render(<App />);
  navigator.serviceWorker?.register('/sw.js', { scope: '/' });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}
