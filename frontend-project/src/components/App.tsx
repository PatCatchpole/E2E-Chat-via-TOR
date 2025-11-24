import React from 'react';


import Chat from './Chat';

const App: React.FC = () => {
    return (
        <div>
            <h1>Chat E2E via Socket.IO</h1>
            <Chat />
        </div>
    );
};

export default App;