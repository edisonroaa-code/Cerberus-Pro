import React, { useState, useRef, useEffect } from 'react';
import { Bot, Send, X, Loader2 } from 'lucide-react';
import { useAuth } from './AuthContext';
import { API_BASE_URL } from '../services/apiConfig';

interface JulesCopilotProps {
    onJobCreated?: (scanId: string) => void;
}

export const JulesCopilot: React.FC<JulesCopilotProps> = ({ onJobCreated }) => {
    const [isOpen, setIsOpen] = useState(false);
    const [command, setCommand] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [messages, setMessages] = useState<{role: 'jules' | 'user', text: string}[]>([
        { role: 'jules', text: 'Hola, soy Jules. Dime qué necesitas auditar y yo me encargo de configurarlo.' }
    ]);
    const { authFetch } = useAuth();
    const endOfMessagesRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (isOpen && endOfMessagesRef.current) {
            endOfMessagesRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [messages, isOpen]);

    const handleSend = async () => {
        if (!command.trim()) return;
        
        const userCmd = command;
        setCommand('');
        setMessages(prev => [...prev, { role: 'user', text: userCmd }]);
        setIsLoading(true);

        try {
            const res = await authFetch(`${API_BASE_URL}/jules/copilot`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: userCmd, autopilot: true }),
            });

            if (!res.ok) {
                const errorData = await res.json().catch(() => null);
                const errorMsg = errorData?.detail || 'Error de conexión con Jules.';
                setMessages(prev => [...prev, { role: 'jules', text: `❌ ${errorMsg}` }]);
                setIsLoading(false);
                return;
            }

            const data = await res.json();
            setMessages(prev => [...prev, { 
                role: 'jules', 
                text: `✅ ${data.message}\nIniciando Job ID: ${data.scanId}` 
            }]);
            
            if (onJobCreated) {
                onJobCreated(data.scanId);
            }
        } catch (error) {
            setMessages(prev => [...prev, { role: 'jules', text: '❌ Ocurrió un error inesperado al contactar con el servidor.' }]);
        } finally {
            setIsLoading(false);
        }
    };

    const handleKeyDown = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    };

    if (!isOpen) {
        return (
            <button 
                onClick={() => setIsOpen(true)}
                className="fixed bottom-6 right-6 p-4 bg-indigo-600 text-white rounded-full shadow-lg hover:bg-indigo-500 transition-colors z-50 flex items-center justify-center animate-pulse-soft focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:ring-offset-2 focus:ring-offset-slate-900"
                title="Abrir Jules Copilot"
            >
                <Bot size={28} />
            </button>
        );
    }

    return (
        <div className="fixed bottom-6 right-6 w-80 sm:w-96 bg-slate-800 border border-slate-700 rounded-lg shadow-2xl z-50 overflow-hidden flex flex-col" style={{ height: '450px' }}>
            {/* Header */}
            <div className="bg-indigo-600 text-white p-3 flex justify-between items-center shadow-md">
                <div className="flex items-center space-x-2">
                    <Bot size={20} />
                    <span className="font-semibold shadow-sm">Jules Copilot</span>
                </div>
                <button 
                    onClick={() => setIsOpen(false)}
                    className="text-white hover:text-indigo-200 transition-colors focus:outline-none"
                    title="Cerrar"
                >
                    <X size={20} />
                </button>
            </div>

            {/* Chat Area */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-slate-900/50 scrollbar-thin scrollbar-thumb-slate-600">
                {messages.map((msg, idx) => (
                    <div key={idx} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                        <div 
                            className={`max-w-[85%] p-3 rounded-lg text-sm whitespace-pre-wrap ${
                                msg.role === 'user' 
                                    ? 'bg-indigo-500 text-white rounded-br-none' 
                                    : 'bg-slate-700 text-slate-200 border border-slate-600 rounded-bl-none'
                            }`}
                        >
                            {msg.text}
                        </div>
                    </div>
                ))}
                {isLoading && (
                    <div className="flex justify-start">
                        <div className="bg-slate-700 p-3 rounded-lg rounded-bl-none flex items-center space-x-2 border border-slate-600">
                            <Loader2 size={16} className="animate-spin text-indigo-400" />
                            <span className="text-sm text-slate-300">Jules está pensando...</span>
                        </div>
                    </div>
                )}
                <div ref={endOfMessagesRef} />
            </div>

            {/* Input Area */}
            <div className="p-3 bg-slate-800 border-t border-slate-700">
                <div className="relative">
                    <textarea
                        value={command}
                        onChange={(e) => setCommand(e.target.value)}
                        onKeyDown={handleKeyDown}
                        placeholder="Ej: Lanza un escaneo rápido a test.com"
                        className="w-full bg-slate-900 text-slate-200 placeholder-slate-500 rounded-lg border border-slate-600 p-3 pr-12 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 resize-none"
                        rows={2}
                        disabled={isLoading}
                    />
                    <button 
                        onClick={handleSend}
                        disabled={!command.trim() || isLoading}
                        className="absolute right-2 bottom-2 p-2 bg-indigo-600 text-white rounded hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        title="Enviar comando"
                    >
                        <Send size={16} />
                    </button>
                </div>
                <div className="mt-2 text-xs text-center text-slate-500">
                    Jules traduce comandos en trabajos de Cerberus Pro.
                </div>
            </div>
        </div>
    );
};
