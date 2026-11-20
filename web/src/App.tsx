import React from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppProvider, useApp } from "./context/AppContext";
import { ClaimPage } from "./pages/ClaimPage";
import { LoginPage } from "./pages/LoginPage";
import { NewProxyNodePage } from "./pages/NewProxyNodePage";
import { NewServerPage } from "./pages/NewServerPage";
import { PoolPage } from "./pages/PoolPage";
import { PortalPage } from "./pages/PortalPage";
import { ProxyNodeDetailPage } from "./pages/ProxyNodeDetailPage";
import { ProxyNodesPage } from "./pages/ProxyNodesPage";
import { ServerCreatedPage } from "./pages/ServerCreatedPage";
import { ServerDetailPage } from "./pages/ServerDetailPage";
import { ServersPage } from "./pages/ServersPage";
import { SettingsPage } from "./pages/SettingsPage";
import { SubscriptionsPage } from "./pages/SubscriptionsPage";
import { UserDetailPage } from "./pages/UserDetailPage";
import { UsersPage } from "./pages/UsersPage";
import { UserSubscriptionPage } from "./pages/UserSubscriptionPage";

const RootRedirect: React.FC = () => {
  const { session, ready } = useApp();
  if (!ready) return null;
  if (session.authenticated && session.role === "admin") return <Navigate to="/servers" replace />;
  if (session.authenticated && session.role === "user") return <Navigate to="/portal" replace />;
  return <Navigate to="/login" replace />;
};

const AppRoutes: React.FC = () => {
  const { ready } = useApp();
  if (!ready) {
    return (
      <div className="loading-state spa-boot-loading" role="status">
        <span className="loading-spinner" aria-hidden="true" />
      </div>
    );
  }
  return (
    <Routes>
      <Route path="/" element={<RootRedirect />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/portal/login" element={<LoginPage />} />
      <Route path="/claim" element={<ClaimPage />} />
      <Route path="/claim/:token" element={<ClaimPage />} />
      <Route path="/portal" element={<PortalPage />} />

      <Route path="/servers" element={<ServersPage />} />
      <Route path="/servers/new" element={<NewServerPage />} />
      <Route path="/servers/enrollment-result" element={<ServerCreatedPage />} />
      <Route path="/servers/:agentId/manage" element={<ServerDetailPage />} />

      <Route path="/proxy-nodes" element={<ProxyNodesPage />} />
      <Route path="/proxy-nodes/new" element={<NewProxyNodePage />} />
      <Route path="/proxy-nodes/:proxyId/manage" element={<ProxyNodeDetailPage />} />
      <Route path="/proxy-nodes/:proxyId/users" element={<Navigate to="../manage?dialog=proxy-node-users" relative="path" replace />} />

      <Route path="/users" element={<UsersPage />} />
      <Route path="/users/:userId" element={<UserDetailPage />} />
      <Route path="/users/:userId/subscription" element={<Navigate to="nodes" replace />} />
      <Route path="/users/:userId/subscription/nodes" element={<UserSubscriptionPage />} />

      <Route path="/subscriptions" element={<SubscriptionsPage />} />
      <Route path="/subscriptions/admin" element={<UserSubscriptionPage />} />

      <Route path="/pool" element={<PoolPage />} />
      <Route path="/settings" element={<SettingsPage />} />
      <Route path="*" element={<RootRedirect />} />
    </Routes>
  );
};

export const App: React.FC = () => (
  <AppProvider>
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  </AppProvider>
);

export default App;
