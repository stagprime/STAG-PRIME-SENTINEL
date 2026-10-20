import { useState } from 'react';
import type { FormEvent } from 'react';
import { Eye, EyeOff, KeyRound, LockKeyhole, ShieldCheck, Server, ArrowRight } from 'lucide-react';
import { signIn } from '../api/auth';
import type { AuthUser } from '../api/auth';
import companyLogo from '../assets/stag-prime-official.svg';
import companyMark from '../assets/stag-prime-symbol.png';
import './SignIn.css';

export default function SignIn({ onSuccess }: { onSuccess: (user: AuthUser) => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      const user = await signIn(username.trim(), password);
      setPassword('');
      onSuccess(user);
    } catch (reason) {
      setPassword('');
      setError(reason instanceof Error ? reason.message : 'Could not sign in.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="sentinel-login">
      <section className="login-story" aria-label="Stag Prime Sentinel">
        <div className="login-brand">
          <img src={companyMark} alt="" />
          <span>STAG PRIME <strong>SENTINEL</strong><small>INFRASTRUCTURE INTELLIGENCE</small></span>
        </div>
        <div className="login-story-content">
          <span className="login-kicker"><ShieldCheck size={16} /> PROTECTED WORKSPACE</span>
          <h1>Every server.<br />Every client.<br /><em>One secure view.</em></h1>
          <p>Role-based infrastructure monitoring for approved teams and client workspaces.</p>
          <div className="login-points">
            <span><Server size={18} /> Multi-client infrastructure</span>
            <span><LockKeyhole size={18} /> Protected server access</span>
            <span><ShieldCheck size={18} /> Stag Prime LLC</span>
          </div>
        </div>
        <div className="login-story-footer">STAG PRIME LLC · SECURE OPERATIONS</div>
      </section>
      <section className="login-auth">
        <div className="login-auth-box">
          <div className="login-official">
            <img src={companyLogo} alt="Stag Prime Digital Agency" />
          </div>
          <span className="login-label">SECURE SIGN IN</span>
          <h2>Welcome back.</h2>
          <p>Sign in with your Sentinel administrator, staff, view, or client account.</p>
          <form onSubmit={submit} autoComplete="on" className="login-form">
            <label htmlFor="sentinel-username">Username</label>
            <div className="login-input-wrap">
              <KeyRound size={18} />
              <input id="sentinel-username" required autoComplete="username" autoCapitalize="none" spellCheck={false} maxLength={80} value={username} onChange={e => setUsername(e.target.value)} placeholder="Your Sentinel username" />
            </div>
            <label htmlFor="sentinel-password">Password</label>
            <div className="login-input-wrap">
              <LockKeyhole size={18} />
              <input id="sentinel-password" required type={showPassword ? 'text' : 'password'} autoComplete="current-password" maxLength={128} value={password} onChange={e => setPassword(e.target.value)} placeholder="Enter your password" />
              <button type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={() => setShowPassword(v => !v)}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button>
            </div>
            {error && <div role="alert" className="login-error">{error}</div>}
            <button className="login-submit" type="submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in to Sentinel'}<ArrowRight size={18} /></button>
          </form>
          <div className="login-footnote">
            <ShieldCheck size={17} />
            <span>Sessions stay on a secure cookie. Passwords are never stored in this browser.</span>
          </div>
        </div>
      </section>
    </main>
  );
}
