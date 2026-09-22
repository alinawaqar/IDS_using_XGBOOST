import { useState } from "react";

export default function Login({ onLogin }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (!password || submitting) return;
    setSubmitting(true);
    setError("");
    try {
      await onLogin(password);
    } catch (err) {
      setError(err.message || "Login failed.");
    } finally {
      setSubmitting(false);
      setPassword("");
    }
  }

  return (
    <div className="login-wrapper">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          LIVE IDS <span>AI Network Defender</span>
        </div>
        <p className="login-subtitle">Sign in to access the dashboard.</p>
        <input
          type="password"
          className="login-input"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
        />
        {error && <div className="login-error">{error}</div>}
        <button className="login-button" type="submit" disabled={submitting}>
          {submitting ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </div>
  );
}