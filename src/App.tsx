import { useState, useEffect, useCallback } from 'react'
import './App.css'
import { fetchSecrets, login } from './lib/api'
import type { SecretDTO } from './interface/SecretDTO'
import {
  hasPin,
  setPin,
  verifyPin,
  isSessionExpired,
  updateLastActivity,
  copyToClipboard,
  setLockTimeout,
  getLockTimeout,
  isBackoffActive,
  getBackoffDelay
} from './lib/security'
import {
  initializeUserKey,
  getKeyFromSession,
  decryptData
} from './lib/crypto'

type Screen = 'loading' | 'login' | 'pin-setup' | 'pin-unlock' | 'main' | 'settings'
type Theme = 'dark' | 'light'

interface DecryptedSecret {
  id: string
  name: string
  username?: string
  password?: string
}

function App() {
  const [screen, setScreen] = useState<Screen>('loading')
  const [secrets, setSecrets] = useState<DecryptedSecret[]>([])
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [, setMasterPassword] = useState("") // Stored temporarily for key derivation
  const [pin, setInputPin] = useState("")
  const [newPin, setNewPin] = useState("")
  const [confirmPin, setConfirmPin] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [lockTimeout, setLockTimeoutState] = useState(5)
  const [isBlurred, setIsBlurred] = useState(false)
  const [backoffRemaining, setBackoffRemaining] = useState(0)
  const [theme, setTheme] = useState<Theme>(() => {
    // Detect system theme or saved preference
    if (typeof localStorage === "undefined") return "dark"
    const savedTheme = localStorage.getItem('ciphervault_theme') as Theme
    if (savedTheme) return savedTheme
    return (typeof window !== "undefined" && window.matchMedia('(prefers-color-scheme: light)').matches) ? 'light' : 'dark'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('ciphervault_theme', theme)
  }, [theme])

  useEffect(() => {
    const handleFocus = () => setIsBlurred(false)
    const handleBlur = () => setIsBlurred(true)

    window.addEventListener('focus', handleFocus)
    window.addEventListener('blur', handleBlur)

    return () => {
      window.removeEventListener('focus', handleFocus)
      window.removeEventListener('blur', handleBlur)
    }
  }, [])

  useEffect(() => {
    let interval: number
    if (backoffRemaining > 0) {
      interval = setInterval(() => {
        setBackoffRemaining(prev => Math.max(0, prev - 1000))
      }, 1000)
    }
    return () => clearInterval(interval)
  }, [backoffRemaining])

  const loadSecrets = useCallback(async () => {
    try {
      const rawSecrets = await fetchSecrets()
      const key = await getKeyFromSession()

      if (!key) {
        console.error("No encryption key available")
        return
      }

      // Decrypt each secret
      const decrypted = await Promise.all(
        rawSecrets.map(async (s: SecretDTO) => {
          try {
            const plaintext = await decryptData(key, s.encryptedData, s.iv)
            const parsed = JSON.parse(plaintext)
            return {
              id: s.id,
              name: parsed.name || `Secret ${s.id.slice(0, 8)}`,
              username: parsed.username,
              password: parsed.password
            }
          } catch {
            return {
              id: s.id,
              name: `Encrypted: ${s.id.slice(0, 8)}...`
            }
          }
        })
      )

      setSecrets(decrypted)
    } catch (e) {
      console.error(e)
    }
  }, [])

  const checkSession = useCallback(async () => {
    const hasPinSet = await hasPin()
    const expired = await isSessionExpired()
    const hasKey = await getKeyFromSession()

    if (hasPinSet && !expired && hasKey) {
      loadSecrets()
      setScreen('main')
    } else if (hasPinSet) {
      setScreen('pin-unlock')
    } else {
      setScreen('login')
    }
  }, [loadSecrets])

  useEffect(() => {
    const init = async () => {
      await checkSession()
      const timeout = await getLockTimeout()
      setLockTimeoutState(timeout)
    }
    init()
  }, [checkSession])

  const handleLogin = async () => {
    setLoading(true)
    setError("")
    try {
      const result = await login(email, password)
      if (result.success) {
        if (!result.data.salt) {
          setError("Account has no encryption key. Please register first.")
          setLoading(false)
          return
        }
        // Derive user's unique encryption key from Master Password + Salt
        await initializeUserKey(password, result.data.salt)
        setMasterPassword(password) // Keep temporarily for PIN setup flow
        await updateLastActivity()

        const hasPinSet = await hasPin()
        if (!hasPinSet) {
          setScreen('pin-setup')
        } else {
          loadSecrets()
          setScreen('main')
        }
      } else {
        const errorMsg = result.error
          ? `[${result.error.code}] ${result.error.message}`
          : "Login failed. Please check your credentials.";
        setError(errorMsg)
      }
    } catch (e: unknown) {
      if (e instanceof Error) {
        // @ts-expect-error - Custom property
        const code = e.code ? `[${e.code}] ` : "";
        setError(code + e.message)
      }
    }
    setLoading(false)
  }

  const handlePinSetup = async () => {
    if (newPin.length < 4 || newPin.length > 6) {
      setError("PIN must be 4-6 digits")
      return
    }
    if (newPin !== confirmPin) {
      setError("PINs do not match")
      return
    }
    await setPin(newPin)
    await updateLastActivity()
    setMasterPassword("") // Clear from memory
    loadSecrets()
    setScreen('main')
  }

  const handlePinUnlock = async () => {
    // Check if backoff is active
    const backoff = await isBackoffActive()
    if (backoff.active) {
      setBackoffRemaining(backoff.remainingMs)
      setError(`Brute-force protection: Please wait ${Math.ceil(backoff.remainingMs / 1000)}s`)
      return
    }

    const valid = await verifyPin(pin)
    if (valid) {
      // Check if we have the key in session
      const key = await getKeyFromSession()
      if (key) {
        loadSecrets()
        setScreen('main')
      } else {
        // Key expired, need to re-login
        setError("Session expired. Please login again.")
        setScreen('login')
      }
    } else {
      const waitTime = await getBackoffDelay()
      if (waitTime > 0) {
        setBackoffRemaining(waitTime)
        setError(`Invalid PIN. Backoff active: ${waitTime / 1000}s`)
      } else {
        setError("Invalid PIN. 5 failed attempts will clear data.")
      }
      setInputPin("")
    }
  }



  const handleFill = (secret: DecryptedSecret) => {
    if (secret.password) {
      // Copy password with auto-clear
      copyToClipboard(secret.password, 30)
    }

    // Send to content script
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]?.id && secret.username && secret.password) {
        chrome.tabs.sendMessage(tabs[0].id, {
          action: 'FILL_CREDENTIALS',
          username: secret.username,
          password: secret.password
        })
      }
    })
  }

  const handleSaveSettings = async () => {
    await setLockTimeout(lockTimeout)
    setScreen('main')
  }

  if (screen === 'loading') {
    return (
      <div className="popup-container">
        <div className="loading">
          <div className="spinner"></div>
        </div>
      </div>
    )
  }

  return (
    <div className={`popup-container ${isBlurred ? 'blurred' : ''}`}>
      <header className="popup-header">
        <div className="header-brand">
          <div className="logo-icon">🔐</div>
          <h1>CipherVault</h1>
        </div>
        <div className="header-actions">
          <div className="theme-toggle">
            <button
              className={theme === 'light' ? 'active' : ''}
              onClick={() => setTheme('light')}
            >
              ☀️
            </button>
            <button
              className={theme === 'dark' ? 'active' : ''}
              onClick={() => setTheme('dark')}
            >
              🌙
            </button>
          </div>
          {screen === 'main' && (
            <>
              <button className="icon-btn" onClick={() => loadSecrets()} title="Refresh">
                🔄
              </button>
              <button className="icon-btn" onClick={() => setScreen('settings')} title="Settings">
                ⚙️
              </button>
            </>
          )}
        </div>
      </header>

      {screen === 'login' && (
        <div className="login-form">
          <h2>Welcome Back</h2>
          <p className="subtitle">Unlock your vault to access your passwords.</p>
          <div className="input-group">
            <span className="input-icon">📧</span>
            <input
              type="email"
              placeholder="Email Address"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div className="input-group">
            <span className="input-icon">🔑</span>
            <input
              type="password"
              placeholder="Master Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </div>
          <button className="btn btn-primary" onClick={handleLogin} disabled={loading}>
            {loading ? <div className="spinner" style={{ width: 16, height: 16 }}></div> : "Unlock Vault"}
          </button>
          {error && <p className="error">{error}</p>}
          <div className="hint" style={{ marginTop: 16 }}>
            <span className="shield-icon">🛡️</span>
            Your password never leaves your device.
          </div>
        </div>
      )}

      {screen === 'pin-setup' && (
        <div className="login-form">
          <h2>Secure with PIN</h2>
          <p className="subtitle">Set a 4-6 digit PIN for quick access.</p>
          <div className="input-group">
            <span className="input-icon">🔢</span>
            <input
              type="password"
              placeholder="New PIN (4-6 digits)"
              value={newPin}
              onChange={(e) => setNewPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
              maxLength={6}
            />
          </div>
          <div className="input-group">
            <span className="input-icon">✅</span>
            <input
              type="password"
              placeholder="Confirm PIN"
              value={confirmPin}
              onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
              maxLength={6}
            />
          </div>
          <button className="btn btn-primary" onClick={handlePinSetup}>Set PIN</button>
          {error && <p className="error">{error}</p>}
        </div>
      )}

      {screen === 'pin-unlock' && (
        <div className="login-form">
          <h2>Identity Verification</h2>
          <p className="subtitle">Enter your PIN to continue.</p>
          <div className="input-group">
            <span className="input-icon">🔢</span>
            <input
              type="password"
              placeholder="PIN"
              value={pin}
              onChange={(e) => setInputPin(e.target.value.replace(/\D/g, '').slice(0, 6))}
              maxLength={6}
              disabled={backoffRemaining > 0}
            />
          </div>
          <button
            className="btn btn-primary"
            onClick={handlePinUnlock}
            disabled={backoffRemaining > 0}
          >
            {backoffRemaining > 0
              ? `Locked (${Math.ceil(backoffRemaining / 1000)}s)`
              : "Verify PIN"}
          </button>
          {error && <p className="error">{error}</p>}
          <div className="hint" style={{ marginTop: 16 }}>
            <button className="btn btn-secondary" style={{ width: '100%' }} onClick={() => setScreen('login')}>
              Use Master Password
            </button>
          </div>
        </div>
      )}

      {screen === 'main' && (
        <div className="secrets-list">
          {secrets.length === 0 ? (
            <div className="empty-state">
              <span className="icon">📂</span>
              <p>No secrets found in this vault.</p>
            </div>
          ) : (
            secrets.map((secret) => (
              <div key={secret.id} className="secret-item" onClick={() => handleFill(secret)}>
                <div className="secret-info">
                  <span className="secret-name">{secret.name}</span>
                  {secret.username && <span className="secret-username">{secret.username}</span>}
                </div>
                <button className="fill-btn">Fill</button>
              </div>
            ))
          )}
        </div>
      )}

      {screen === 'settings' && (
        <div className="settings-panel">
          <h3>Settings</h3>
          <div className="setting-item">
            <label>Auto-lock timeout</label>
            <select
              value={lockTimeout}
              onChange={(e) => setLockTimeoutState(Number(e.target.value))}
            >
              <option value={1}>1 minute</option>
              <option value={5}>5 minutes</option>
              <option value={15}>15 minutes</option>
              <option value={30}>30 minutes</option>
            </select>
          </div>
          <div className="setting-item" style={{ border: 'none', background: 'none', padding: 0 }}>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleSaveSettings}>
              Save Settings
            </button>
          </div>
          <button onClick={() => setScreen('main')} className="btn btn-secondary">
            Go Back
          </button>

          <div style={{ marginTop: 'auto' }}>
            <button className="btn btn-secondary" style={{ width: '100%', color: 'var(--error)' }} onClick={() => setScreen('login')}>
              Lock Vault
            </button>
          </div>
        </div>
      )}

      <footer className="popup-footer">
        <div className="security-badge">
          🛡️ Zero-Knowledge Encrypted
        </div>
        <div style={{ marginTop: 8 }}>
          <a href="http://localhost:3000/dashboard" target="_blank" rel="noreferrer">Open CipherVault Web</a>
        </div>
      </footer>
    </div>
  )
}

export default App
