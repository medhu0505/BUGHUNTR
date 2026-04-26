import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { DashboardLayout } from "@/components/DashboardLayout";
import DashboardOverview from "@/pages/DashboardOverview";
import ScannerPage from "@/pages/ScannerPage";
import ScanAllPage from "@/pages/ScanAllPage";
import ReportsCenter from "@/pages/ReportsCenter";
import AboutPage from "@/pages/AboutPage";
import ScanHistoryPage from "@/pages/ScanHistoryPage";
import NotFound from "@/pages/NotFound";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 15_000,
    },
  },
});

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Sonner theme="dark" />
      <BrowserRouter>
        <DashboardLayout>
          <Routes>
            <Route path="/" element={<DashboardOverview />} />
            <Route path="/scanner/:moduleId" element={<ScannerPage />} />
            <Route path="/scan-all" element={<ScanAllPage />} />
            <Route path="/reports" element={<ReportsCenter />} />
            <Route path="/history" element={<ScanHistoryPage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </DashboardLayout>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
