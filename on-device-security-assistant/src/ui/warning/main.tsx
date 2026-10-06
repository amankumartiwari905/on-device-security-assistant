import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '../styles.css';
import { WarningPage } from './WarningPage';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <WarningPage />
  </StrictMode>,
);