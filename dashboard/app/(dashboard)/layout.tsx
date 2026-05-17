import BgCanvas from "@/components/canvas/BgCanvas";
import TopBar from "@/components/layout/TopBar";
import SideBar from "@/components/layout/SideBar";
import Ticker from "@/components/layout/Ticker";
import ToastContainer from "@/components/ui/Toast";
import ModalContainer from "@/components/ui/Modal";
import CopilotFab from "@/components/copilot/CopilotFab";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <>
      <BgCanvas opacity={0.35} />
      <div className="scanlines" />
      <TopBar />
      <SideBar />
      <main className="content">{children}</main>
      <Ticker className="ticker-bar" />
      <CopilotFab variant="dashboard" />
      <ToastContainer />
      <ModalContainer />
    </>
  );
}
