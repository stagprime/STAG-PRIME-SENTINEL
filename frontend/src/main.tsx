import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import SignIn from './components/SignIn.tsx'
import { useEffect, useState } from 'react'
import { restoreSession, signOut } from './api/auth'
import type { AuthUser } from './api/auth'
import './SentinelEnterpriseTheme.css'

function SentinelShell() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [checking, setChecking] = useState(true);
  const [checkError, setCheckError] = useState<string | null>(null);
  useEffect(() => {
    const expire = () => { setUser(null); setChecking(false); };
    window.addEventListener('sentinel:auth-expired', expire);
    const controller = new AbortController();
    restoreSession(controller.signal)
      .then((restored) => { if (!controller.signal.aborted) { setUser(restored); setCheckError(null); } })
      .catch(() => { if (!controller.signal.aborted) setCheckError('Could not verify your session. Check that the backend is running and reload.'); })
      .finally(() => { if (!controller.signal.aborted) setChecking(false); });
    return () => { controller.abort(); window.removeEventListener('sentinel:auth-expired', expire); };
  }, []);
  async function logout() {
    try { await signOut(); setUser(null); }
    catch { window.alert('Sign out could not be confirmed by the server. Please retry.'); }
  }
  if (checking) return <div role="status" style={{padding:'12vh 10vw',fontFamily:'system-ui',color:'#123451'}}>Verifying secure Sentinel session…</div>;
  if (checkError) return <main style={{padding:'12vh 10vw',fontFamily:'system-ui'}} role="alert"><h2>Connection unavailable</h2><p>{checkError}</p><button onClick={() => window.location.reload()}>Retry</button></main>;
  return user ? <App currentUser={user} onSignOut={logout} /> : <SignIn onSuccess={setUser} />;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SentinelShell />
  </StrictMode>,
)
