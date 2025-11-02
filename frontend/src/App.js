import { useState } from 'react';
import './App.css';
import CreateSecret from './components/CreateSecret';
import ViewSecret from './components/ViewSecret';

function App() {
  const [currentView, setCurrentView] = useState('create');
  const [generatedUrl, setGeneratedUrl] = useState('');

  return (
    <div className="App">
      <header className="App-header">
        <h1>Secret Share</h1>
        <nav>
          <button
            onClick={() => setCurrentView('create')}
            className={currentView === 'create' ? 'active' : ''}
          >
            Create Secret
          </button>
          <button
            onClick={() => setCurrentView('view')}
            className={currentView === 'view' ? 'active' : ''}
          >
            View Secret
          </button>
        </nav>
      </header>

      <main>
        {currentView === 'create' ? (
          <CreateSecret onSecretCreated={setGeneratedUrl} />
        ) : (
          <ViewSecret />
        )}

        {generatedUrl && (
          <div className="url-display">
            <h3>Your secret has been created!</h3>
            <p>Share this URL:</p>
            <div className="url-box">
              <input
                type="text"
                value={generatedUrl}
                readOnly
                onClick={(e) => e.target.select()}
              />
              <button
                onClick={() => navigator.clipboard.writeText(generatedUrl)}
                className="copy-btn"
              >
                Copy
              </button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;