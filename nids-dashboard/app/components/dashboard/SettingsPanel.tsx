"use client";

import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { startSnifferWithConfig, stopSnifferApi, updateMLConfig, updateSnifferConfig } from "@/lib/api";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { HelpCircle, Play, Square, Save } from "lucide-react";

export function SettingsPanel() {
  const [iface, setIface] = useState<string>("Loopback Pseudo-Interface 1");
  const [pktCount, setPktCount] = useState<number>(1000);
  const [timeout, setTimeoutVal] = useState<number>(30);
  const [bpf, setBpf] = useState<string>("");

  const [modelPath, setModelPath] = useState<string>("app/ml_models/nids_model.joblib");
  const [confidence, setConfidence] = useState<number>(0.8);

  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>("");

  const handleStart = async () => {
    try {
      setBusy(true);
      setMessage("");
      const config = {
        interface: iface,
        packet_count: pktCount,
        timeout: timeout,
        filter: bpf || undefined,
      };
      await startSnifferWithConfig(config);
      setMessage("Sniffer started successfully");
    } catch (e: any) {
      setMessage(e?.message || "Failed to start sniffer");
    } finally {
      setBusy(false);
    }
  };

  const handleStop = async () => {
    try {
      setBusy(true);
      setMessage("");
      await stopSnifferApi();
      setMessage("Sniffer stopped successfully");
    } catch (e: any) {
      setMessage(e?.message || "Failed to stop sniffer");
    } finally {
      setBusy(false);
    }
  };

  const handleSaveConfigs = async () => {
    try {
      setBusy(true);
      setMessage("");
      await updateSnifferConfig({
        interface: iface,
        packet_count: pktCount,
        timeout: timeout,
        filter: bpf || undefined,
      });
      await updateMLConfig({
        model_path: modelPath,
        confidence_threshold: confidence,
      });
      setMessage("Configurations updated");
    } catch (e: any) {
      setMessage(e?.message || "Failed to update configurations");
    } finally {
      setBusy(false);
    }
  };

  return (
    <TooltipProvider>
      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Sniffer Settings</CardTitle>
            <CardDescription>Configure network capture</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="iface">Interface</Label>
              <Input id="iface" value={iface} onChange={(e) => setIface(e.target.value)} />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="pkt">Packet Count</Label>
                <Input id="pkt" type="number" value={pktCount} onChange={(e) => setPktCount(parseInt(e.target.value || "0"))} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="timeout">Timeout (s)</Label>
                <Input id="timeout" type="number" value={timeout} onChange={(e) => setTimeoutVal(parseInt(e.target.value || "0"))} />
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <Label htmlFor="bpf">BPF Filter</Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <HelpCircle className="h-3.5 w-3.5 text-muted-foreground" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p className="text-xs">Optional Berkeley Packet Filter (e.g., "tcp port 80")</p>
                  </TooltipContent>
                </Tooltip>
              </div>
              <Input id="bpf" value={bpf} onChange={(e) => setBpf(e.target.value)} placeholder="tcp or udp port 53" />
            </div>
            <div className="flex items-center gap-2">
              <Button onClick={handleStart} disabled={busy}>
                <Play className="mr-2 h-4 w-4" /> Start
              </Button>
              <Button variant="destructive" onClick={handleStop} disabled={busy}>
                <Square className="mr-2 h-4 w-4" /> Stop
              </Button>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>ML Settings</CardTitle>
            <CardDescription>Model configuration</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="model">Model Path</Label>
              <Input id="model" value={modelPath} onChange={(e) => setModelPath(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label htmlFor="conf">Confidence Threshold</Label>
              <Input id="conf" type="number" step="0.01" min="0" max="1" value={confidence} onChange={(e) => setConfidence(parseFloat(e.target.value || "0"))} />
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" onClick={handleSaveConfigs} disabled={busy}>
                <Save className="mr-2 h-4 w-4" /> Save Configurations
              </Button>
            </div>
            {message && (
              <div className="text-sm text-muted-foreground">
                <Badge variant="outline">{message}</Badge>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </TooltipProvider>
  );
}
