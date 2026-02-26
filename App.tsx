import React, { Suspense } from 'react';

const AppRuntime = React.lazy(() => import('./AppRuntime'));

const App: React.FC = () => {
    return (
        <Suspense fallback={<div className="flex h-screen items-center justify-center bg-cyber-950 text-emerald-500">Cargando sistema de seguridad...</div>}>
            <AppRuntime />
        </Suspense>
    );
};

export default App;
