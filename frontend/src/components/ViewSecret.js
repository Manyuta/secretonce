import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import './ViewSecret.css';

const ViewSecret = () => {
  const { metadata_key } = useParams();
  const [secretData, setSecretData] = useState(null);
  const [passphrase, setPassphrase] = useState('');
  const [decryptionKey, setDecryptionKey] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [secretRevealed, setSecretRevealed] = useState(false);

  useEffect(() => {
    if (metadata_key) {
      fetchSecretMetadata();
    }
  }, [metadata_key]);

  const fetchSecretMetadata = async () => {
    try {
      const response = await fetch(`/api/v1/secret/${metadata_key}`);
      if (response.ok) {
        const data = await response.json();
        setSecretData(data);
      } else if (response.status === 404) {
        setError('Secret not found or has expired');
      } else {
        throw new Error('Failed to fetch secret metadata');
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');

    try {
      const payload = {};

      if (secretData.passphrase_required) {
        payload.passphrase = passphrase;
      } else {
        payload.decryption_key = decryptionKey;
      }

      const response = await fetch(`/api/v1/secret/${metadata_key}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to retrieve secret');
      }

      const data = await response.json();
      setSecretData(prev => ({ ...prev, value: data.value }));
      setSecretRevealed(true);

    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  if (!metadata_key) {
    return (
      <div className="view-secret">
        <h2>View Secret</h2>
        <p>Enter a secret URL to view its contents.</p>
      </div>
    );
  }

  if (error && !secretData) {
    return (
      <div className="view-secret">
        <h2>Secret Not Available</h2>
        <div className="error-message">{error}</div>
      </div>
    );
  }

  if (secretRevealed && secretData?.value) {
    return (
      <div className="view-secret">
        <h2>Your Secret</h2>
        <div className="secret-revealed">
          <div className="secret-content">{secretData.value}</div>
          <div className="secret-info">
            <p>This secret has been viewed and will self-destruct.</p>
            <button onClick={() => window.close()} className="close-btn">
              Close Window
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="view-secret">
      <h2>Secret Access Required</h2>

      {secretData && (
        <div className="secret-metadata">
          <p>This secret requires {secretData.passphrase_required ? 'a passphrase' : 'a decryption key'} to access.</p>
          <div className="metadata-info">
            <span>Views remaining: {secretData.views_remaining}</span>
            <span>Expires in: {Math.ceil(secretData.ttl_remaining / 60)} hours</span>
          </div>
        </div>
      )}

      <form onSubmit={handleSubmit} className="access-form">
        {secretData?.passphrase_required ? (
          <div className="form-group">
            <label htmlFor="passphrase">Enter Passphrase</label>
            <input
              type="password"
              id="passphrase"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Enter the passphrase"
              required
            />
          </div>
        ) : (
          <div className="form-group">
            <label htmlFor="decryptionKey">Enter Decryption Key</label>
            <input
              type="text"
              id="decryptionKey"
              value={decryptionKey}
              onChange={(e) => setDecryptionKey(e.target.value)}
              placeholder="Enter the decryption key"
              required
            />
          </div>
        )}

        {error && <div className="error-message">{error}</div>}

        <button
          type="submit"
          disabled={isLoading}
          className="submit-btn"
        >
          {isLoading ? 'Decrypting...' : 'Reveal Secret'}
        </button>
      </form>
    </div>
  );
};

export default ViewSecret;