'use client';
import { useTheme } from './ThemeProvider';
import { Sun, Moon } from 'lucide-react';

export function ThemeToggle() {
  const { theme, toggle } = useTheme();

  return (
    <button
      onClick={toggle}
      aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      className="
        fixed bottom-6 right-6 z-50
        h-11 w-11 rounded-full
        flex items-center justify-center
        bg-slate-800 border border-slate-700
        text-slate-300 hover:text-white
        hover:bg-slate-700
        shadow-lg shadow-black/30
        transition-all duration-200
      "
    >
      {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
    </button>
  );
}
