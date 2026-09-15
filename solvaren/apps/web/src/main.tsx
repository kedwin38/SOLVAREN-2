import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.js';
import './styles/system.css';

// Theme: honour the OS preference, persisted per browser once the user chooses.
const stored = localStorage.getItem('solvaren.theme');
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
document.documentElement.dataset.theme = stored ?? (prefersDark ? 'dark' : 'light');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
