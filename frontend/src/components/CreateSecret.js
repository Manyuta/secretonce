// components/CreateSecret.js
import React, { useState } from 'react';
import './CreateSecret.css';

const CreateSecret = ({ onSecretCreated }) => {
  const [formData, setFormData] = useState({
    secret: '',
    maxViews: 1,
    ttl: 1440, // 24 hours in minutes
    passphrase: '',
    usePassphrase: false
  });
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [createdSecret, setCreatedSecret] = useState(null);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    setCreatedSecret(null);

    try {
      const payload = {
        secret: formData.secret,
        max_views: parseInt(formData.maxViews),
        ttl: parseInt(formData.ttl)
      };

      if (formData.usePassphrase && formData.passphrase) {
        payload.passphrase = formData.passphrase;
      }

      const response = await fetch('/api/v1/secret', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error('Failed to create secret');
      }

      const data = await response.json();

      // Construct the URL for viewing the secret
      const baseUrl = window.location.origin;
      const viewUrl = `${baseUrl}/secret/${data.secret_key}`;

      // Store the created secret data
      setCreatedSecret({
        viewUrl,
        decryptionKey: data.decryption_key,
        secretId: data.secret_key,
        encryptionType: data.encryption_type
      });

      onSecretCreated(viewUrl);

      // Reset form
      setFormData({
        secret: '',
        maxViews: 1,
        ttl: 1440,
        passphrase: '',
        usePassphrase: false
      });

    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const ttlOptions = [
    { value: 60, label: '1 hour' },
    { value: 1440, label: '1 day' },
    { value: 10080, label: '1 week' },
    { value: 43200, label: '1 month' },
    { value: 'custom', label: 'Custom' }
  ];

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
    alert('Copied to clipboard!');
  };

  return (
    <div className="create-secret">
      <h2>Create a New Secret</h2>

      {createdSecret ? (
        <div className="secret-created">
          <h3> Secret Created Successfully!</h3>

          <div className="secret-info">
            <div className="info-item">
              <label>Share this URL:</label>
              <div className="copy-box">
                <input
                  type="text"
                  value={createdSecret.viewUrl}
                  readOnly
                />
                <button
                  onClick={() => copyToClipboard(createdSecret.viewUrl)}
                  className="copy-btn"
                >
                  Copy URL
                </button>
              </div>
            </div>

            {createdSecret.decryptionKey && (
              <div className="info-item">
                <label>🔑 Decryption Key (Save this!):</label>
                <div className="copy-box">
                  <input
                    type="text"
                    value={createdSecret.decryptionKey}
                    readOnly
                    className="decryption-key"
                  />
                  <button
                    onClick={() => copyToClipboard(createdSecret.decryptionKey)}
                    className="copy-btn"
                  >
                    Copy Key
                  </button>
                </div>
                <p className="warning-text">
                  ⚠️ This key will not be shown again. Anyone with this key can decrypt your secret.
                </p>
              </div>
            )}

            {!createdSecret.decryptionKey && (
              <div className="info-item">
                <p>🔒 This secret is protected with a passphrase.</p>
              </div>
            )}

            <div className="info-item">
              <p><strong>Secret ID:</strong> {createdSecret.secretId}</p>
              <p><strong>Encryption Type:</strong> {createdSecret.encryptionType}</p>
            </div>

            <button
              onClick={() => setCreatedSecret(null)}
              className="create-another-btn"
            >
              Create Another Secret
            </button>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="secret-form">
          <div className="form-group">
            <label htmlFor="secret">Your Secret *</label>
            <textarea
              id="secret"
              name="secret"
              value={formData.secret}
              onChange={handleChange}
              placeholder="Enter the secret text you want to share..."
              required
              rows="4"
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label htmlFor="maxViews">Maximum Views</label>
              <input
                type="number"
                id="maxViews"
                name="maxViews"
                value={formData.maxViews}
                onChange={handleChange}
                min="1"
                max="100"
                placeholder="Enter number of views"
              />
              <p className="help-text">Number of times this secret can be viewed (1-100)</p>
            </div>

            <div className="form-group">
              <label htmlFor="ttl">Expires After</label>
              <select
                id="ttl"
                name="ttl"
                value={formData.ttl}
                onChange={handleChange}
              >
                {ttlOptions.map(option => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              {formData.ttl === 'custom' && (
                <input
                  type="number"
                  name="ttlCustom"
                  placeholder="Minutes"
                  min="1"
                  onChange={(e) => setFormData(prev => ({ ...prev, ttl: e.target.value }))}
                />
              )}
            </div>
          </div>

          <div className="form-group checkbox-group">
            <label>
              <input
                type="checkbox"
                name="usePassphrase"
                checked={formData.usePassphrase}
                onChange={handleChange}
              />
              Protect with passphrase
            </label>
            <p className="help-text">
              {formData.usePassphrase
                ? "Recipients will need the passphrase to view the secret"
                : "A decryption key will be generated that recipients need to view the secret"
              }
            </p>
          </div>

          {formData.usePassphrase && (
            <div className="form-group">
              <label htmlFor="passphrase">Passphrase</label>
              <input
                type="password"
                id="passphrase"
                name="passphrase"
                value={formData.passphrase}
                onChange={handleChange}
                placeholder="Enter a passphrase to protect your secret"
              />
            </div>
          )}

          {error && <div className="error-message">{error}</div>}

          <button
            type="submit"
            disabled={isLoading || !formData.secret.trim() || formData.maxViews < 1 || formData.maxViews > 100}
            className="submit-btn"
          >
            {isLoading ? 'Creating...' : 'Create Secret'}
          </button>
        </form>
      )}
    </div>
  );
};

export default CreateSecret;