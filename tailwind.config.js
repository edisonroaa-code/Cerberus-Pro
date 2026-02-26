/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                cyber: {
                    950: '#020617',
                    900: '#0f172a',
                    800: '#1e293b',
                    700: '#334155',
                    primary: '#10b981', // Emerald 500
                    accent: '#06b6d4', // Cyan 500
                    danger: '#ef4444',
                    warning: '#f59e0b',
                }
            },
            fontFamily: {
                mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', "Liberation Mono", "Courier New", 'monospace'],
                sans: ['ui-sans-serif', 'system-ui', '-apple-system', "Segoe UI", 'Roboto', "Helvetica Neue", 'Arial', "Noto Sans", 'sans-serif'],
            }
        },
    },
    plugins: [],
}
