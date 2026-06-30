import { useState, useEffect } from "react";
import { getUsers, createUser, deleteUser, ApiError, BACKEND_UNAVAILABLE, type UserInfo } from "../api";
import { useAuth } from "../AuthContext";

function apiErrorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    return err.status === 0 ? BACKEND_UNAVAILABLE : err.message;
  }
  return BACKEND_UNAVAILABLE;
}

export default function UsersPage() {
  const { invalidateSession } = useAuth();
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("analyst");
  const [formError, setFormError] = useState("");

  const loadUsers = () => {
    setLoading(true);
    setError("");
    getUsers()
      .then(setUsers)
      .catch((err) => {
        setUsers([]);
        setError(apiErrorMessage(err));
        if (err instanceof ApiError && (err.status === 0 || err.status === 401)) {
          invalidateSession(apiErrorMessage(err));
        }
      })
      .finally(() => setLoading(false));
  };

  useEffect(loadUsers, [invalidateSession]);

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");

    try {
      await createUser({ email: newEmail, password: newPassword, role: newRole });
      setNewEmail("");
      setNewPassword("");
      setNewRole("analyst");
      setShowForm(false);
      loadUsers();
    } catch (err) {
      setFormError(apiErrorMessage(err));
      if (err instanceof ApiError && (err.status === 0 || err.status === 401)) {
        invalidateSession(apiErrorMessage(err));
      }
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await deleteUser(id);
      loadUsers();
    } catch (err) {
      setError(apiErrorMessage(err));
      if (err instanceof ApiError && (err.status === 0 || err.status === 401)) {
        invalidateSession(apiErrorMessage(err));
      }
    }
  };

  if (loading) {
    return <div className="page-container"><p>Loading users...</p></div>;
  }

  if (error) {
    return <div className="page-container"><p style={{ color: "red" }}>{error}</p></div>;
  }

  return (
    <div className="page-container">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
        <h1>User Management</h1>
        <button className="btn-primary" onClick={() => setShowForm(!showForm)}>
          {showForm ? "Cancel" : "Add User"}
        </button>
      </div>

      {showForm && (
        <div style={{ border: "1px solid #ddd", padding: 16, marginBottom: 20, background: "#fafafa" }}>
          <h3 style={{ marginBottom: 12 }}>New User</h3>
          {formError && (
            <div style={{ background: "#fee", color: "#c00", padding: "8px 12px", marginBottom: 12, borderRadius: 4, fontSize: 13 }}>
              {formError}
            </div>
          )}
          <form onSubmit={handleAddUser}>
            <div style={{ marginBottom: 8 }}>
              <label>Email</label>
              <input
                type="email"
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                placeholder="user@penguwave.io"
                required
              />
            </div>
            <div style={{ marginBottom: 8 }}>
              <label>Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="password"
                required
              />
            </div>
            <div style={{ marginBottom: 12 }}>
              <label>Role</label>
              <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
            <button type="submit" className="btn-primary">
              Create User
            </button>
          </form>
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.id}>
              <td>{user.email}</td>
              <td>{user.role}</td>
              <td>
                <span style={{ color: user.status === "active" ? "green" : "#999" }}>
                  {user.status}
                </span>
              </td>
              <td>
                <a
                  href="#"
                  onClick={(e) => {
                    e.preventDefault();
                    handleDelete(user.id);
                  }}
                  style={{ color: "red" }}
                >
                  Delete
                </a>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {users.length === 0 && <p style={{ color: "#999" }}>No users.</p>}
    </div>
  );
}
