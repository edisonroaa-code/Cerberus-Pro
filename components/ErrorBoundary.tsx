import React, { ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

interface Props {
    children: ReactNode;
}

interface State {
    hasError: boolean;
    error?: Error;
}

class ErrorBoundary extends React.Component<Props, State> {
    constructor(props: Props) {
        super(props);
        this.state = {
            hasError: false
        };
    }

    public static getDerivedStateFromError(error: Error): State {
        return { hasError: true, error };
    }

    public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error('[ErrorBoundary] Uncaught error:', error, errorInfo);
    }

    public render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6 text-white font-sans">
                    <div className="max-w-md w-full bg-slate-900 border border-red-500/30 rounded-xl p-8 shadow-2xl shadow-red-500/10">
                        <div className="flex items-center gap-4 mb-6">
                            <div className="p-3 bg-red-500/10 rounded-lg">
                                <ShieldAlert className="w-8 h-8 text-red-500" />
                            </div>
                            <h1 className="text-2xl font-bold text-red-500">Error Crítico</h1>
                        </div>

                        <p className="text-slate-400 mb-6 leading-relaxed">
                            La interfaz de Cerberus Pro ha encontrado un error inesperado. Esto puede deberse a un problema de renderizado o una respuesta corrupta del motor.
                        </p>

                        {this.state.error && (
                            <div className="bg-black/40 rounded-lg p-4 mb-8 font-mono text-xs text-red-300/80 overflow-auto max-h-32 border border-red-500/20">
                                {this.state.error.toString()}
                            </div>
                        )}

                        <button
                            onClick={() => window.location.reload()}
                            className="w-full flex items-center justify-center gap-2 bg-red-600 hover:bg-red-500 text-white font-bold py-3 px-6 rounded-lg transition-all active:scale-95 shadow-lg shadow-red-600/20"
                        >
                            <RefreshCw className="w-5 h-5" />
                            Reiniciar Interfaz
                        </button>
                    </div>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
