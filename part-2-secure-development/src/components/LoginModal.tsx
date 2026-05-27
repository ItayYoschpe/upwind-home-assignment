import { useState } from "react";
import { login as apiLogin, ApiError, BACKEND_UNAVAILABLE } from "../api";
import { useAuth } from "../AuthContext";

export default function LoginModal() {
  const { login, sessionError, clearSessionError } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const displayError = error || sessionError;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    clearSessionError();
    setSubmitting(true);

    try {
      const data = await apiLogin(email, password);
      login(data.token, data.user);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.status === 0 ? BACKEND_UNAVAILABLE : err.message);
      } else {
        setError(BACKEND_UNAVAILABLE);
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="modal-backdrop">
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <h2>Sign In</h2>
        <p style={{ color: "#666", marginBottom: 20, fontSize: 14 }}>
          Enter your credentials to access PenguWave
        </p>
        {displayError && (
          <div style={{ background: "#fee", color: "#c00", padding: "8px 12px", marginBottom: 12, borderRadius: 4, fontSize: 13 }}>
            {displayError}
          </div>
        )}
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: 12 }}>
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              required
            />
          </div>
          <div style={{ marginBottom: 16 }}>
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              required
            />
          </div>
          <button type="submit" className="btn-primary" style={{ width: "100%" }} disabled={submitting}>
            {submitting ? "Signing in..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}
