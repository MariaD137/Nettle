import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./AuthContext";
import LoginPage from "./pages/LoginPage";
import DashboardPage from "./pages/DashboardPage";
import ProjectPage from "./pages/ProjectPage";
import BillingResultPage from "./pages/BillingResultPage";
import SettingsPage from "./pages/SettingsPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import SubscribePage from "./pages/SubscribePage";
import { CustomRulesPage } from "./pages/CustomRulesPage";
import { AnalyticsPage } from "./pages/AnalyticsPage";
import { hasActiveSubscription } from "./subscription";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="shell muted">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

/**
 * The paywall guard. Signed in but unpaid accounts get the plan picker
 * instead of the dashboard — there is no partial dashboard to fall back to.
 * The API enforces the same rule independently, so this is the UX half of
 * the gate, not the security half.
 */
function PaidRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="shell muted">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  if (!hasActiveSubscription(user)) return <Navigate to="/subscribe" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route
        path="/subscribe"
        element={
          <ProtectedRoute>
            <SubscribePage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/"
        element={
          <PaidRoute>
            <DashboardPage />
          </PaidRoute>
        }
      />
      <Route
        path="/projects/:id"
        element={
          <PaidRoute>
            <ProjectPage />
          </PaidRoute>
        }
      />
      <Route
        path="/projects/:projectId/custom-rules"
        element={
          <PaidRoute>
            <CustomRulesPage />
          </PaidRoute>
        }
      />
      <Route
        path="/projects/:projectId/analytics"
        element={
          <PaidRoute>
            <AnalyticsPage />
          </PaidRoute>
        }
      />
      {/* Account settings stay reachable unpaid, so a lapsed customer can
          still change their password or close their account. */}
      <Route
        path="/settings"
        element={
          <ProtectedRoute>
            <SettingsPage />
          </ProtectedRoute>
        }
      />
      <Route path="/billing/success" element={<BillingResultPage outcome="success" />} />
      <Route path="/billing/cancelled" element={<BillingResultPage outcome="cancelled" />} />
    </Routes>
  );
}
