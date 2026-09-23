import { Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./AuthContext";
import LoginPage from "./pages/LoginPage";
import MarketingPage from "./pages/MarketingPage";
import DashboardPage from "./pages/DashboardPage";
import ProjectPage from "./pages/ProjectPage";
import BillingResultPage from "./pages/BillingResultPage";
import SettingsPage from "./pages/SettingsPage";
import ResetPasswordPage from "./pages/ResetPasswordPage";
import SubscribePage from "./pages/SubscribePage";

/**
 * Every signed-in account gets a real (if capped) dashboard now — FREE
 * included (pricing rework: 1 project, sample content, no real scans, no
 * Fix Center). There is no separate "unpaid -> /subscribe" redirect
 * anymore; individual dashboard/project features that are actually BUILD+
 * or PROTECT-only are gated where they live (DashboardPage, ProjectPage),
 * driven by what the API actually returns — the API enforces the real rule
 * independently, so this is UX framing, not the security boundary.
 */
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="shell muted">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

/**
 * "/" specifically: the one route a signed-out visitor can land on without
 * being bounced straight to a login form.
 */
function HomeRoute() {
  const { user, loading } = useAuth();
  if (loading) return <div className="shell muted">Loading…</div>;
  if (!user) return <MarketingPage />;
  return <DashboardPage />;
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
      <Route path="/" element={<HomeRoute />} />
      {/* Same content as the signed-out "/" page, but reachable regardless
          of auth state — FREE accounts need a real, in-app way to see the
          control-library preview and sample findings the pricing model
          promises them, not just whatever they saw before signing up. */}
      <Route path="/explore" element={<MarketingPage />} />
      <Route
        path="/projects/:id"
        element={
          <ProtectedRoute>
            <ProjectPage />
          </ProtectedRoute>
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
