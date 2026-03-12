'use client';

import { createContext, useContext, useEffect, useState, ReactNode } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextType {
    theme: Theme;
    toggleTheme: () => void;
}

const ThemeContext = createContext<ThemeContextType>({
    theme: 'light',
    toggleTheme: () => { },
});

export function useTheme() {
    return useContext(ThemeContext);
}

export default function ThemeProvider({ children }: { children: ReactNode }) {
    const [theme, setTheme] = useState<Theme>('light');
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
        const saved = localStorage.getItem('library-theme') as Theme;
        if (saved) {
            setTheme(saved);
            document.documentElement.classList.toggle('dark', saved === 'dark');
        }
    }, []);

    const toggleTheme = () => {
        const next = theme === 'light' ? 'dark' : 'light';
        setTheme(next);
        localStorage.setItem('library-theme', next);
        document.documentElement.classList.toggle('dark', next === 'dark');
    };

    if (!mounted) {
        return <div style={{ visibility: 'hidden' }}>{children}</div>;
    }

    return (
        <ThemeContext.Provider value={{ theme, toggleTheme }}>
            {children}
        </ThemeContext.Provider>
    );
}
