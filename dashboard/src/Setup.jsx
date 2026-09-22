import { useState } from "react";

export default function Setup({ onSetup }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    if (submitting) return;
    if (password.length < 8) {
      setError("Use at least 8 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    setSubmitting(true);
    setError("");
    try {
      await onSetup(password);
    } catch (err) {
      setError(err.message || "Setup failed.");
      setSubmitting(false);
    }
  }

  return (
    <div className="login-wrapper">
      <form className="login-card" onSubmit={handleSubmit}>
        <div className="login-brand">
          LIVE IDS <span>AI Network Defender</span>
        </div>
        <p className="login-subtitle">
          First-time setup — choose a password for this dashboard. You'll use
          it to log in from now on.
        </p>
        <input
          type="password"
          className="login-input"
          placeholder="New password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
        />
        <input
          type="password"
          className="login-input"
          placeholder="Confirm password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
        {error && <div className="login-error">{error}</div>}
        <button className="login-button" type="submit" disabled={submitting}>
          {submitting ? "Setting up..." : "Create password"}
        </button>
      </form>
    </div>
  );
}