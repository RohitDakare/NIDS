"use client"

import { useState, useEffect, useMemo } from "react"
import {
  Bell,
  Shield,
  Activity,
  Network,
  AlertTriangle,
  CheckCircle,
  Eye,
  Filter,
  Download,
  Settings,
  Moon,
  Sun,
  Search,
  MapPin,
  TrendingUp,
  Globe,
  Cpu,
  HardDrive,
  Wifi,
  Lock,
  Play,
  Pause,
  RotateCcw,
  ChevronDown,
  X,
  Plus,
  RefreshCw,
  Calendar,
  FileText,
  Target,
} from "lucide-react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Progress } from "@/components/ui/progress"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { Slider } from "@/components/ui/slider"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import {
  Line,
  LineChart,
  AreaChart,
  Area,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  Legend,
  ResponsiveContainer,
} from "recharts"
import { Upload } from "lucide-react"
import { fetchAlerts, fetchPackets, fetchSystemStatus } from "../lib/api"

// Mock data generators for demo purposes
function generateThreatIntelData() {
  return [
    { type: "Malware", count: 12, trend: "+3" },
    { type: "Phishing", count: 7, trend: "-1" },
    { type: "Ransomware", count: 5, trend: "+2" },
    { type: "DDoS", count: 3, trend: "+1" },
  ];
}

function generateGeoData() {
  return [
    { country: "USA", attacks: 20 },
    { country: "China", attacks: 15 },
    { country: "Russia", attacks: 10 },
    { country: "Brazil", attacks: 5 },
    { country: "India", attacks: 3 },
  ];
}

export default function EnhancedNIDSDashboard() {
  const [darkMode, setDarkMode] = useState(false)
  const [activeTab, setActiveTab] = useState("dashboard")
  const [trafficData, setTrafficData] = useState([])
  const [alerts, setAlerts] = useState([])
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [isRealTimeEnabled, setIsRealTimeEnabled] = useState(true)
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedFilters, setSelectedFilters] = useState({
    severity: "all",
    status: "all",
    timeRange: "24h",
  })
  const [systemHealth, setSystemHealth] = useState({
    status: "unknown",
    uptime: "-",
    packetsProcessed: 0,
    detectionRate: 0,
    falsePositiveRate: 0,
    cpuUsage: 0,
    memoryUsage: 0,
    diskUsage: 0,
    networkUtilization: 0,
  })
  const [packets, setPackets] = useState([])

  // Fetch real data from backend
  useEffect(() => {
    async function loadData() {
      try {
        const alertsRes = await fetchAlerts(100)
        setAlerts(alertsRes.alerts || [])
        const packetsRes = await fetchPackets(100)
        setPackets(packetsRes.packets || [])
        const statusRes = await fetchSystemStatus()
        setSystemHealth({
          status: statusRes.status || "unknown",
          uptime: statusRes.uptime || "-",
          packetsProcessed: statusRes.packets_processed || 0,
          detectionRate: statusRes.detection_rate || 0,
          falsePositiveRate: statusRes.false_positive_rate || 0,
          cpuUsage: statusRes.cpu_usage || 0,
          memoryUsage: statusRes.memory_usage || 0,
          diskUsage: statusRes.disk_usage || 0,
          networkUtilization: statusRes.network_utilization || 0,
        })
        // Optionally, set trafficData from packetsRes or statusRes if available
        // setTrafficData(...)
      } catch (err) {
        // Handle error, optionally show notification
        console.error("Failed to load NIDS data", err)
      }
    }
    loadData()
    if (isRealTimeEnabled) {
      const interval = setInterval(loadData, 5000)
      return () => clearInterval(interval)
    }
  }, [isRealTimeEnabled])

  // Filtered alerts based on search and filters
  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const matchesSearch =
        searchQuery === "" ||
        alert.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
        alert.sourceIP.includes(searchQuery) ||
        alert.destIP.includes(searchQuery)

      const matchesSeverity = selectedFilters.severity === "all" || alert.severity === selectedFilters.severity
      const matchesStatus = selectedFilters.status === "all" || alert.status === selectedFilters.status

      return matchesSearch && matchesSeverity && matchesStatus
    })
  }, [alerts, searchQuery, selectedFilters])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "destructive"
      case "high":
        return "destructive"
      case "medium":
        return "default"
      case "low":
        return "secondary"
      default:
        return "secondary"
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "new":
        return "destructive"
      case "investigating":
        return "default"
      case "acknowledged":
        return "secondary"
      case "resolved":
        return "outline"
      case "blocked":
        return "outline"
      default:
        return "secondary"
    }
  }

  const formatTimeAgo = (timestamp: Date) => {
    const now = new Date()
    const diffMs = now.getTime() - timestamp.getTime()
    const diffMins = Math.floor(diffMs / 60000)

    if (diffMins < 1) return "Just now"
    if (diffMins < 60) return `${diffMins}m ago`
    const diffHours = Math.floor(diffMins / 60)
    if (diffHours < 24) return `${diffHours}h ago`
    const diffDays = Math.floor(diffHours / 24)
    return `${diffDays}d ago`
  }

  const handleAlertAction = (alertId: number, action: string) => {
    setAlerts((prev) =>
      prev.map((alert) =>
        alert.id === alertId ? { ...alert, status: action === "acknowledge" ? "acknowledged" : action } : alert,
      ),
    )
  }

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.ctrlKey || event.metaKey) {
        switch (event.key) {
          case "1":
            event.preventDefault()
            setActiveTab("dashboard")
            break
          case "2":
            event.preventDefault()
            setActiveTab("alerts")
            break
          case "3":
            event.preventDefault()
            setActiveTab("packets")
            break
          case "4":
            event.preventDefault()
            setActiveTab("system")
            break
          case "k":
            event.preventDefault()
            document.getElementById("search-input")?.focus()
            break
        }
      }
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [])

  return (
    <TooltipProvider>
      <div className={`min-h-screen ${darkMode ? "dark" : ""}`}>
        <div className="flex h-screen bg-background">
          {/* Enhanced Sidebar */}
          <div className="w-64 border-r bg-card/50 backdrop-blur-sm">
            <div className="p-6">
              <div className="flex items-center gap-2 mb-8">
                <div className="relative">
                  <Shield className="h-8 w-8 text-primary" />
                  <div className="absolute -top-1 -right-1 h-3 w-3 bg-green-500 rounded-full animate-pulse" />
                </div>
                <div>
                  <h1 className="text-xl font-bold">NIDS Monitor</h1>
                  <p className="text-xs text-muted-foreground">v2.1.3</p>
                </div>
              </div>

              <nav className="space-y-2">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant={activeTab === "dashboard" ? "default" : "ghost"}
                      className="w-full justify-start"
                      onClick={() => setActiveTab("dashboard")}
                    >
                      <Activity className="mr-2 h-4 w-4" />
                      Dashboard
                      <kbd className="ml-auto text-xs bg-muted px-1 rounded">⌘1</kbd>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="right">
                    <p>Main dashboard overview</p>
                  </TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant={activeTab === "alerts" ? "default" : "ghost"}
                      className="w-full justify-start"
                      onClick={() => setActiveTab("alerts")}
                    >
                      <Bell className="mr-2 h-4 w-4" />
                      Alerts
                      <Badge variant="destructive" className="ml-auto text-xs">
                        {alerts.filter((a) => a.status === "new").length}
                      </Badge>
                      <kbd className="ml-2 text-xs bg-muted px-1 rounded">⌘2</kbd>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="right">
                    <p>Security alerts and incidents</p>
                  </TooltipContent>
                </Tooltip>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant={activeTab === "packets" ? "default" : "ghost"}
                      className="w-full justify-start"
                      onClick={() => setActiveTab("packets")}
                    >
                      <Network className="mr-2 h-4 w-4" />
                      Packet Explorer
                      <kbd className="ml-auto text-xs bg-muted px-1 rounded">⌘3</kbd>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="right">
                    <p>Deep packet inspection and analysis</p>
                  </TooltipContent>
                </Tooltip>

                <Button
                  variant={activeTab === "threat-intel" ? "default" : "ghost"}
                  className="w-full justify-start"
                  onClick={() => setActiveTab("threat-intel")}
                >
                  <Target className="mr-2 h-4 w-4" />
                  Threat Intel
                </Button>

                <Button
                  variant={activeTab === "reports" ? "default" : "ghost"}
                  className="w-full justify-start"
                  onClick={() => setActiveTab("reports")}
                >
                  <FileText className="mr-2 h-4 w-4" />
                  Reports
                </Button>

                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant={activeTab === "system" ? "default" : "ghost"}
                      className="w-full justify-start"
                      onClick={() => setActiveTab("system")}
                    >
                      <Settings className="mr-2 h-4 w-4" />
                      System Status
                      <kbd className="ml-auto text-xs bg-muted px-1 rounded">⌘4</kbd>
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="right">
                    <p>System health and configuration</p>
                  </TooltipContent>
                </Tooltip>
              </nav>

              <Separator className="my-6" />

              {/* Quick Stats */}
              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">System Status</span>
                  <div className="flex items-center gap-1">
                    <div className="h-2 w-2 bg-green-500 rounded-full animate-pulse" />
                    <span className="text-green-500 font-medium">Healthy</span>
                  </div>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Active Threats</span>
                  <span className="font-medium text-destructive">
                    {alerts.filter((a) => a.status === "new").length}
                  </span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">Packets/sec</span>
                  <span className="font-medium">~2.4K</span>
                </div>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1 flex flex-col">
            {/* Enhanced Header */}
            <header className="border-b bg-card/50 backdrop-blur-sm px-6 py-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <h2 className="text-2xl font-semibold capitalize">{activeTab.replace("-", " ")}</h2>
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => setIsRealTimeEnabled(!isRealTimeEnabled)}>
                      {isRealTimeEnabled ? <Pause className="mr-2 h-4 w-4" /> : <Play className="mr-2 h-4 w-4" />}
                      {isRealTimeEnabled ? "Pause" : "Resume"}
                    </Button>
                    <Button variant="outline" size="sm">
                      <RefreshCw className="mr-2 h-4 w-4" />
                      Refresh
                    </Button>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="search-input"
                      placeholder="Search... (⌘K)"
                      className="pl-10 w-64"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="outline" size="sm">
                        <Download className="mr-2 h-4 w-4" />
                        Export
                        <ChevronDown className="ml-2 h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent>
                      <DropdownMenuItem>
                        <FileText className="mr-2 h-4 w-4" />
                        Export as PDF
                      </DropdownMenuItem>
                      <DropdownMenuItem>
                        <Download className="mr-2 h-4 w-4" />
                        Export as CSV
                      </DropdownMenuItem>
                      <DropdownMenuItem>
                        <Calendar className="mr-2 h-4 w-4" />
                        Schedule Report
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                  <div className="flex items-center space-x-2">
                    <Sun className="h-4 w-4" />
                    <Switch checked={darkMode} onCheckedChange={setDarkMode} aria-label="Toggle dark mode" />
                    <Moon className="h-4 w-4" />
                  </div>
                </div>
              </div>
            </header>

            {/* Enhanced Content */}
            <main className="flex-1 p-6 overflow-auto">
              {activeTab === "dashboard" && (
                <div className="space-y-6">
                  {/* Enhanced Summary Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                    <Card className="relative overflow-hidden">
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Total Packets</CardTitle>
                        <Network className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{systemHealth.packetsProcessed.toLocaleString()}</div>
                        <p className="text-xs text-muted-foreground">+12% from last hour</p>
                        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-500 to-purple-500" />
                      </CardContent>
                    </Card>

                    <Card className="relative overflow-hidden">
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Active Alerts</CardTitle>
                        <AlertTriangle className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold text-destructive">
                          {alerts.filter((a) => a.status === "new").length}
                        </div>
                        <p className="text-xs text-muted-foreground">
                          {alerts.filter((a) => a.severity === "critical").length} critical
                        </p>
                        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-red-500 to-orange-500" />
                      </CardContent>
                    </Card>

                    <Card className="relative overflow-hidden">
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">System Health</CardTitle>
                        <CheckCircle className="h-4 w-4 text-green-500" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold text-green-500">Healthy</div>
                        <p className="text-xs text-muted-foreground">Uptime: {systemHealth.uptime}</p>
                        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-green-500 to-emerald-500" />
                      </CardContent>
                    </Card>

                    <Card className="relative overflow-hidden">
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Detection Rate</CardTitle>
                        <Activity className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{systemHealth.detectionRate}%</div>
                        <p className="text-xs text-muted-foreground">FP Rate: {systemHealth.falsePositiveRate}%</p>
                        <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-cyan-500 to-blue-500" />
                      </CardContent>
                    </Card>
                  </div>

                  {/* Enhanced Charts Grid */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <div>
                            <CardTitle>Network Traffic Analysis</CardTitle>
                            <CardDescription>Real-time packet flow with anomaly detection</CardDescription>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="text-xs">
                              {isRealTimeEnabled ? "LIVE" : "PAUSED"}
                            </Badge>
                            <Button variant="outline" size="sm">
                              <TrendingUp className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <ResponsiveContainer width="100%" height={300}>
                          <AreaChart data={trafficData}>
                            <defs>
                              <linearGradient id="packetsGradient" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#8884d8" stopOpacity={0.8} />
                                <stop offset="95%" stopColor="#8884d8" stopOpacity={0.1} />
                              </linearGradient>
                              <linearGradient id="anomaliesGradient" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#ff7300" stopOpacity={0.8} />
                                <stop offset="95%" stopColor="#ff7300" stopOpacity={0.1} />
                              </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="time" />
                            <YAxis />
                            <RechartsTooltip
                              contentStyle={{
                                backgroundColor: "hsl(var(--card))",
                                border: "1px solid hsl(var(--border))",
                                borderRadius: "8px",
                              }}
                            />
                            <Area
                              type="monotone"
                              dataKey="packets"
                              stroke="#8884d8"
                              fill="url(#packetsGradient)"
                              name="Packets"
                            />
                            <Area
                              type="monotone"
                              dataKey="anomalies"
                              stroke="#ff7300"
                              fill="url(#anomaliesGradient)"
                              name="Anomalies"
                            />
                          </AreaChart>
                        </ResponsiveContainer>
                      </CardContent>
                    </Card>

                    {/* Remove or comment out the protocol distribution chart that uses protocolData
                    // If you want to re-enable it in the future, fetch protocol stats from the backend /api/v1/stats endpoint if available */}
                    {/* <Card>
                      <CardHeader>
                        <CardTitle>Protocol Distribution</CardTitle>
                        <CardDescription>Traffic breakdown by protocol type</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 gap-4">
                          <ResponsiveContainer width="100%" height={200}>
                            <PieChart>
                              <Pie
                                data={protocolData}
                                cx="50%"
                                cy="50%"
                                innerRadius={40}
                                outerRadius={80}
                                paddingAngle={5}
                                dataKey="value"
                              >
                                {protocolData.map((entry, index) => (
                                  <Cell key={`cell-${index}`} fill={entry.color} />
                                ))}
                              </Pie>
                              <RechartsTooltip />
                            </PieChart>
                          </ResponsiveContainer>
                          <div className="space-y-2">
                            {protocolData.map((protocol, index) => (
                              <div key={index} className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: protocol.color }} />
                                  <span className="text-sm font-medium">{protocol.name}</span>
                                </div>
                                <div className="text-right">
                                  <div className="text-sm font-bold">{protocol.value}%</div>
                                  <div className="text-xs text-muted-foreground">
                                    {protocol.packets.toLocaleString()}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      </CardContent>
                    </Card> */}
                  </div>

                  {/* New: Threat Intelligence and Geographic View */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Remove or comment out the Threat Intelligence Feed section that uses generateThreatIntelData
                    // If you want to re-enable it in the future, fetch threat intel data from the backend if available */}
                    {/* <Card>
                      <CardHeader>
                        <CardTitle>Threat Intelligence Feed</CardTitle>
                        <CardDescription>Latest threat patterns and indicators</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          {generateThreatIntelData().map((threat, index) => (
                            <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                              <div className="flex items-center gap-3">
                                <div className="w-2 h-2 bg-red-500 rounded-full" />
                                <div>
                                  <p className="font-medium">{threat.type}</p>
                                  <p className="text-sm text-muted-foreground">{threat.count} incidents</p>
                                </div>
                              </div>
                              <Badge variant={threat.trend.startsWith("+") ? "destructive" : "secondary"}>
                                {threat.trend}
                              </Badge>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card> */}

                    {/* Remove or comment out the Geographic Threat Distribution section that uses generateGeoData
                    // If you want to re-enable it in the future, fetch geo data from the backend if available */}
                    {/* <Card>
                      <CardHeader>
                        <CardTitle>Geographic Threat Distribution</CardTitle>
                        <CardDescription>Attack sources by country</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {generateGeoData().map((country, index) => (
                            <div key={index} className="flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                <MapPin className="h-4 w-4 text-muted-foreground" />
                                <span className="font-medium">{country.country}</span>
                              </div>
                              <div className="flex items-center gap-2">
                                <div className="w-20 bg-muted rounded-full h-2">
                                  <div
                                    className="bg-red-500 h-2 rounded-full"
                                    style={{ width: `${(country.attacks / 50) * 100}%` }}
                                  />
                                </div>
                                <span className="text-sm font-bold w-8 text-right">{country.attacks}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card> */}
                  </div>

                  {/* Enhanced Live Alerts Feed */}
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div>
                          <CardTitle>Live Alerts Feed</CardTitle>
                          <CardDescription>Recent security alerts requiring attention</CardDescription>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button variant="outline" size="sm">
                            <Filter className="mr-2 h-4 w-4" />
                            Filter
                          </Button>
                          <Button variant="outline" size="sm">
                            Mark All Read
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-80">
                        <div className="space-y-3">
                          {filteredAlerts.slice(0, 10).map((alert) => (
                            <div
                              key={alert.id}
                              className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                            >
                              <div className="flex items-center gap-4">
                                <div className="flex flex-col items-center gap-1">
                                  <Badge variant={getSeverityColor(alert.severity)} className="text-xs">
                                    {alert.severity.toUpperCase()}
                                  </Badge>
                                  <div className="text-xs text-muted-foreground">{alert.confidence}%</div>
                                </div>
                                <div className="flex-1">
                                  <div className="flex items-center gap-2 mb-1">
                                    <p className="font-medium">{alert.type}</p>
                                    <Badge variant="outline" className="text-xs">
                                      {alert.protocol}
                                    </Badge>
                                  </div>
                                  <p className="text-sm text-muted-foreground mb-1">
                                    {alert.sourceIP} → {alert.destIP}:{alert.port}
                                  </p>
                                  <p className="text-xs text-muted-foreground">{alert.description}</p>
                                </div>
                              </div>
                              <div className="flex items-center gap-3">
                                <div className="text-right">
                                  <div className="text-sm font-medium">{formatTimeAgo(alert.timestamp)}</div>
                                  <div className="text-xs text-muted-foreground">{alert.relatedAlerts} related</div>
                                </div>
                                <div className="flex gap-1">
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <Button size="sm" variant="outline">
                                        <Eye className="h-4 w-4" />
                                      </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                      <p>View details</p>
                                    </TooltipContent>
                                  </Tooltip>
                                  <Tooltip>
                                    <TooltipTrigger asChild>
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        onClick={() => handleAlertAction(alert.id, "acknowledge")}
                                      >
                                        <CheckCircle className="h-4 w-4" />
                                      </Button>
                                    </TooltipTrigger>
                                    <TooltipContent>
                                      <p>Acknowledge</p>
                                    </TooltipContent>
                                  </Tooltip>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* Enhanced Alerts Page */}
              {activeTab === "alerts" && (
                <div className="space-y-6">
                  {/* Advanced Filters */}
                  <Card>
                    <CardContent className="pt-6">
                      <div className="flex flex-wrap gap-4 items-center">
                        <div className="relative flex-1 min-w-64">
                          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                          <Input
                            placeholder="Search alerts, IPs, or descriptions..."
                            className="pl-10"
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                          />
                        </div>
                        <Select
                          value={selectedFilters.severity}
                          onValueChange={(value) => setSelectedFilters((prev) => ({ ...prev, severity: value }))}
                        >
                          <SelectTrigger className="w-40">
                            <SelectValue placeholder="Severity" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All Severities</SelectItem>
                            <SelectItem value="critical">Critical</SelectItem>
                            <SelectItem value="high">High</SelectItem>
                            <SelectItem value="medium">Medium</SelectItem>
                            <SelectItem value="low">Low</SelectItem>
                          </SelectContent>
                        </Select>
                        <Select
                          value={selectedFilters.status}
                          onValueChange={(value) => setSelectedFilters((prev) => ({ ...prev, status: value }))}
                        >
                          <SelectTrigger className="w-40">
                            <SelectValue placeholder="Status" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="all">All Status</SelectItem>
                            <SelectItem value="new">New</SelectItem>
                            <SelectItem value="investigating">Investigating</SelectItem>
                            <SelectItem value="acknowledged">Acknowledged</SelectItem>
                            <SelectItem value="resolved">Resolved</SelectItem>
                            <SelectItem value="blocked">Blocked</SelectItem>
                          </SelectContent>
                        </Select>
                        <Select
                          value={selectedFilters.timeRange}
                          onValueChange={(value) => setSelectedFilters((prev) => ({ ...prev, timeRange: value }))}
                        >
                          <SelectTrigger className="w-32">
                            <SelectValue placeholder="Time Range" />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="1h">Last Hour</SelectItem>
                            <SelectItem value="24h">Last 24h</SelectItem>
                            <SelectItem value="7d">Last 7 days</SelectItem>
                            <SelectItem value="30d">Last 30 days</SelectItem>
                          </SelectContent>
                        </Select>
                        <Button variant="outline">
                          <Filter className="mr-2 h-4 w-4" />
                          Advanced
                        </Button>
                        <Button variant="outline">
                          <Download className="mr-2 h-4 w-4" />
                          Export ({filteredAlerts.length})
                        </Button>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Enhanced Alerts Table */}
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div>
                          <CardTitle>Security Alerts ({filteredAlerts.length})</CardTitle>
                          <CardDescription>Manage and investigate security incidents</CardDescription>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button variant="outline" size="sm">
                            <Plus className="mr-2 h-4 w-4" />
                            Create Rule
                          </Button>
                          <Button variant="outline" size="sm">
                            Bulk Actions
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="rounded-md border">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead className="w-12">
                                <Checkbox />
                              </TableHead>
                              <TableHead>Alert</TableHead>
                              <TableHead>Source → Destination</TableHead>
                              <TableHead>Confidence</TableHead>
                              <TableHead>Time</TableHead>
                              <TableHead>Status</TableHead>
                              <TableHead className="text-right">Actions</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {filteredAlerts.map((alert) => (
                              <TableRow key={alert.id} className="hover:bg-muted/50">
                                <TableCell>
                                  <Checkbox />
                                </TableCell>
                                <TableCell>
                                  <div className="flex items-center gap-3">
                                    <Badge variant={getSeverityColor(alert.severity)} className="text-xs">
                                      {alert.severity.charAt(0).toUpperCase()}
                                    </Badge>
                                    <div>
                                      <div className="font-medium">{alert.type}</div>
                                      <div className="text-sm text-muted-foreground flex items-center gap-2">
                                        <Badge variant="outline" className="text-xs">
                                          {alert.protocol}
                                        </Badge>
                                        <span>Rule: {alert.ruleId}</span>
                                      </div>
                                    </div>
                                  </div>
                                </TableCell>
                                <TableCell>
                                  <div className="font-mono text-sm">
                                    <div className="flex items-center gap-2">
                                      <span>{alert.sourceIP}</span>
                                      <span className="text-muted-foreground">→</span>
                                      <span>
                                        {alert.destIP}:{alert.port}
                                      </span>
                                    </div>
                                    <div className="text-xs text-muted-foreground mt-1">{alert.geoLocation}</div>
                                  </div>
                                </TableCell>
                                <TableCell>
                                  <div className="flex items-center gap-2">
                                    <div className="w-16 bg-muted rounded-full h-2">
                                      <div
                                        className={`h-2 rounded-full ${
                                          alert.confidence >= 90
                                            ? "bg-green-500"
                                            : alert.confidence >= 70
                                              ? "bg-yellow-500"
                                              : "bg-red-500"
                                        }`}
                                        style={{ width: `${alert.confidence}%` }}
                                      />
                                    </div>
                                    <span className="text-sm font-medium">{alert.confidence}%</span>
                                  </div>
                                </TableCell>
                                <TableCell>
                                  <div className="text-sm">
                                    <div>{formatTimeAgo(alert.timestamp)}</div>
                                    <div className="text-xs text-muted-foreground">{alert.relatedAlerts} related</div>
                                  </div>
                                </TableCell>
                                <TableCell>
                                  <Badge variant={getStatusColor(alert.status)}>{alert.status}</Badge>
                                </TableCell>
                                <TableCell className="text-right">
                                  <div className="flex justify-end gap-1">
                                    <Dialog>
                                      <DialogTrigger asChild>
                                        <Button size="sm" variant="outline">
                                          <Eye className="h-4 w-4" />
                                        </Button>
                                      </DialogTrigger>
                                      <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                                        <DialogHeader>
                                          <DialogTitle className="flex items-center gap-2">
                                            Alert Details
                                            <Badge variant={getSeverityColor(alert.severity)}>{alert.severity}</Badge>
                                          </DialogTitle>
                                          <DialogDescription>
                                            Comprehensive analysis of security incident #{alert.id}
                                          </DialogDescription>
                                        </DialogHeader>
                                        <Tabs defaultValue="overview" className="w-full">
                                          <TabsList className="grid w-full grid-cols-4">
                                            <TabsTrigger value="overview">Overview</TabsTrigger>
                                            <TabsTrigger value="technical">Technical</TabsTrigger>
                                            <TabsTrigger value="context">Context</TabsTrigger>
                                            <TabsTrigger value="response">Response</TabsTrigger>
                                          </TabsList>
                                          <TabsContent value="overview" className="space-y-4">
                                            <div className="grid grid-cols-2 gap-4">
                                              <Card>
                                                <CardHeader className="pb-3">
                                                  <CardTitle className="text-sm">Alert Information</CardTitle>
                                                </CardHeader>
                                                <CardContent className="space-y-2">
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Type:</span>
                                                    <span className="text-sm font-medium">{alert.type}</span>
                                                  </div>
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Severity:</span>
                                                    <Badge variant={getSeverityColor(alert.severity)}>
                                                      {alert.severity}
                                                    </Badge>
                                                  </div>
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Confidence:</span>
                                                    <span className="text-sm font-medium">{alert.confidence}%</span>
                                                  </div>
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Rule ID:</span>
                                                    <code className="text-sm">{alert.ruleId}</code>
                                                  </div>
                                                </CardContent>
                                              </Card>
                                              <Card>
                                                <CardHeader className="pb-3">
                                                  <CardTitle className="text-sm">Network Details</CardTitle>
                                                </CardHeader>
                                                <CardContent className="space-y-2">
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Source IP:</span>
                                                    <code className="text-sm">{alert.sourceIP}</code>
                                                  </div>
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Destination:</span>
                                                    <code className="text-sm">
                                                      {alert.destIP}:{alert.port}
                                                    </code>
                                                  </div>
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Protocol:</span>
                                                    <Badge variant="outline">{alert.protocol}</Badge>
                                                  </div>
                                                  <div className="flex justify-between">
                                                    <span className="text-sm text-muted-foreground">Location:</span>
                                                    <span className="text-sm">{alert.geoLocation}</span>
                                                  </div>
                                                </CardContent>
                                              </Card>
                                            </div>
                                            <Card>
                                              <CardHeader className="pb-3">
                                                <CardTitle className="text-sm">Description</CardTitle>
                                              </CardHeader>
                                              <CardContent>
                                                <p className="text-sm">{alert.description}</p>
                                              </CardContent>
                                            </Card>
                                          </TabsContent>
                                          <TabsContent value="technical" className="space-y-4">
                                            <Card>
                                              <CardHeader>
                                                <CardTitle className="text-sm">Payload Analysis</CardTitle>
                                              </CardHeader>
                                              <CardContent>
                                                <div className="bg-muted p-4 rounded-lg">
                                                  <code className="text-sm">{alert.payload}</code>
                                                </div>
                                              </CardContent>
                                            </Card>
                                            <Card>
                                              <CardHeader>
                                                <CardTitle className="text-sm">Detection Logic</CardTitle>
                                              </CardHeader>
                                              <CardContent>
                                                <p className="text-sm text-muted-foreground">
                                                  This alert was triggered by rule {alert.ruleId} which monitors for{" "}
                                                  {alert.type.toLowerCase()} patterns.
                                                </p>
                                              </CardContent>
                                            </Card>
                                          </TabsContent>
                                          <TabsContent value="context" className="space-y-4">
                                            <Card>
                                              <CardHeader>
                                                <CardTitle className="text-sm">
                                                  Related Alerts ({alert.relatedAlerts})
                                                </CardTitle>
                                              </CardHeader>
                                              <CardContent>
                                                <p className="text-sm text-muted-foreground">
                                                  {alert.relatedAlerts} related alerts found in the last 24 hours from
                                                  the same source.
                                                </p>
                                              </CardContent>
                                            </Card>
                                            <Card>
                                              <CardHeader>
                                                <CardTitle className="text-sm">Threat Intelligence</CardTitle>
                                              </CardHeader>
                                              <CardContent>
                                                <p className="text-sm text-muted-foreground">
                                                  Source IP {alert.sourceIP} has been flagged in threat intelligence
                                                  feeds.
                                                </p>
                                              </CardContent>
                                            </Card>
                                          </TabsContent>
                                          <TabsContent value="response" className="space-y-4">
                                            <div className="grid grid-cols-2 gap-4">
                                              <Button className="w-full">
                                                <Lock className="mr-2 h-4 w-4" />
                                                Block Source IP
                                              </Button>
                                              <Button variant="outline" className="w-full bg-transparent">
                                                <CheckCircle className="mr-2 h-4 w-4" />
                                                Acknowledge Alert
                                              </Button>
                                              <Button variant="outline" className="w-full bg-transparent">
                                                <X className="mr-2 h-4 w-4" />
                                                Mark False Positive
                                              </Button>
                                              <Button variant="outline" className="w-full bg-transparent">
                                                <Plus className="mr-2 h-4 w-4" />
                                                Create Custom Rule
                                              </Button>
                                            </div>
                                            <Card>
                                              <CardHeader>
                                                <CardTitle className="text-sm">Response Notes</CardTitle>
                                              </CardHeader>
                                              <CardContent>
                                                <Textarea
                                                  placeholder="Add investigation notes or response actions taken..."
                                                  className="min-h-20"
                                                />
                                                <Button className="mt-2" size="sm">
                                                  Save Notes
                                                </Button>
                                              </CardContent>
                                            </Card>
                                          </TabsContent>
                                        </Tabs>
                                      </DialogContent>
                                    </Dialog>
                                    <DropdownMenu>
                                      <DropdownMenuTrigger asChild>
                                        <Button size="sm" variant="outline">
                                          <ChevronDown className="h-4 w-4" />
                                        </Button>
                                      </DropdownMenuTrigger>
                                      <DropdownMenuContent align="end">
                                        <DropdownMenuItem onClick={() => handleAlertAction(alert.id, "acknowledge")}>
                                          <CheckCircle className="mr-2 h-4 w-4" />
                                          Acknowledge
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => handleAlertAction(alert.id, "investigating")}>
                                          <Eye className="mr-2 h-4 w-4" />
                                          Start Investigation
                                        </DropdownMenuItem>
                                        <DropdownMenuItem onClick={() => handleAlertAction(alert.id, "blocked")}>
                                          <Lock className="mr-2 h-4 w-4" />
                                          Block & Resolve
                                        </DropdownMenuItem>
                                        <DropdownMenuSeparator />
                                        <DropdownMenuItem>
                                          <X className="mr-2 h-4 w-4" />
                                          Mark False Positive
                                        </DropdownMenuItem>
                                      </DropdownMenuContent>
                                    </DropdownMenu>
                                  </div>
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* Enhanced Packet Explorer */}
              {activeTab === "packets" && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <Card className="lg:col-span-2">
                      <CardHeader>
                        <CardTitle>Live Packet Stream</CardTitle>
                        <CardDescription>Real-time packet capture and analysis</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div className="flex items-center gap-4">
                            <Button variant="outline" size="sm">
                              <Play className="mr-2 h-4 w-4" />
                              Start Capture
                            </Button>
                            <Button variant="outline" size="sm">
                              <Pause className="mr-2 h-4 w-4" />
                              Pause
                            </Button>
                            <Button variant="outline" size="sm">
                              <Download className="mr-2 h-4 w-4" />
                              Export PCAP
                            </Button>
                            <Separator orientation="vertical" className="h-6" />
                            <Select>
                              <SelectTrigger className="w-40">
                                <SelectValue placeholder="Interface" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="eth0">eth0</SelectItem>
                                <SelectItem value="eth1">eth1</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div className="border rounded-lg">
                            <Table>
                              <TableHeader>
                                <TableRow>
                                  <TableHead>Time</TableHead>
                                  <TableHead>Source</TableHead>
                                  <TableHead>Destination</TableHead>
                                  <TableHead>Protocol</TableHead>
                                  <TableHead>Size</TableHead>
                                  <TableHead>Anomaly Score</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {packets.map((packet) => (
                                  <TableRow key={packet.id} className="hover:bg-muted/50">
                                    <TableCell className="font-mono text-sm">
                                      {packet.timestamp.toLocaleTimeString()}
                                    </TableCell>
                                    <TableCell className="font-mono text-sm">{packet.sourceIP}</TableCell>
                                    <TableCell className="font-mono text-sm">{packet.destIP}</TableCell>
                                    <TableCell>
                                      <Badge variant="outline">{packet.protocol}</Badge>
                                    </TableCell>
                                    <TableCell>{packet.size} bytes</TableCell>
                                    <TableCell>
                                      <div className="flex items-center gap-2">
                                        <div className="w-16 bg-muted rounded-full h-2">
                                          <div
                                            className={`h-2 rounded-full ${
                                              packet.anomalyScore >= 0.8
                                                ? "bg-red-500"
                                                : packet.anomalyScore >= 0.6
                                                  ? "bg-yellow-500"
                                                  : "bg-green-500"
                                            }`}
                                            style={{ width: `${packet.anomalyScore * 100}%` }}
                                          />
                                        </div>
                                        <span className="text-sm font-medium">
                                          {(packet.anomalyScore * 100).toFixed(0)}%
                                        </span>
                                      </div>
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Packet Analysis</CardTitle>
                        <CardDescription>Deep inspection tools</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div>
                            <Label className="text-sm font-medium">Filter Expression</Label>
                            <Input placeholder="tcp port 80 or udp port 53" className="mt-1 font-mono text-sm" />
                          </div>
                          <div>
                            <Label className="text-sm font-medium">Anomaly Threshold</Label>
                            <Slider defaultValue={[80]} max={100} step={1} className="mt-2" />
                            <div className="flex justify-between text-xs text-muted-foreground mt-1">
                              <span>0%</span>
                              <span>100%</span>
                            </div>
                          </div>
                          <Separator />
                          <div className="space-y-2">
                            <h4 className="text-sm font-medium">Quick Filters</h4>
                            <div className="grid grid-cols-2 gap-2">
                              <Button variant="outline" size="sm" className="text-xs bg-transparent">
                                HTTP Traffic
                              </Button>
                              <Button variant="outline" size="sm" className="text-xs bg-transparent">
                                DNS Queries
                              </Button>
                              <Button variant="outline" size="sm" className="text-xs bg-transparent">
                                SSH Sessions
                              </Button>
                              <Button variant="outline" size="sm" className="text-xs bg-transparent">
                                Anomalies Only
                              </Button>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  <Card>
                    <CardHeader>
                      <CardTitle>Packet Details</CardTitle>
                      <CardDescription>Select a packet above to view detailed analysis</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="text-center py-12">
                        <Network className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                        <h3 className="text-lg font-medium mb-2">No Packet Selected</h3>
                        <p className="text-muted-foreground">
                          Click on a packet in the stream above to view its detailed analysis, including header
                          information, payload, and ML feature vectors.
                        </p>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* New Threat Intelligence Tab */}
              {activeTab === "threat-intel" && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>Threat Feeds</CardTitle>
                        <CardDescription>External threat intelligence sources</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          {[
                            { name: "MISP Feed", status: "active", lastUpdate: "2 min ago", threats: 1247 },
                            { name: "AlienVault OTX", status: "active", lastUpdate: "5 min ago", threats: 892 },
                            { name: "VirusTotal", status: "active", lastUpdate: "1 min ago", threats: 2156 },
                            { name: "Shodan", status: "warning", lastUpdate: "15 min ago", threats: 445 },
                          ].map((feed, index) => (
                            <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                              <div className="flex items-center gap-3">
                                <div
                                  className={`w-2 h-2 rounded-full ${
                                    feed.status === "active" ? "bg-green-500" : "bg-yellow-500"
                                  }`}
                                />
                                <div>
                                  <p className="font-medium">{feed.name}</p>
                                  <p className="text-sm text-muted-foreground">
                                    {feed.threats.toLocaleString()} indicators
                                  </p>
                                </div>
                              </div>
                              <div className="text-right">
                                <p className="text-sm font-medium">{feed.lastUpdate}</p>
                                <Badge variant={feed.status === "active" ? "default" : "secondary"}>
                                  {feed.status}
                                </Badge>
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>IOC Analysis</CardTitle>
                        <CardDescription>Indicators of Compromise detection</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div className="grid grid-cols-3 gap-4">
                            <div className="text-center">
                              <div className="text-2xl font-bold text-red-500">23</div>
                              <div className="text-sm text-muted-foreground">Malicious IPs</div>
                            </div>
                            <div className="text-center">
                              <div className="text-2xl font-bold text-yellow-500">7</div>
                              <div className="text-sm text-muted-foreground">Suspicious Domains</div>
                            </div>
                            <div className="text-center">
                              <div className="text-2xl font-bold text-blue-500">12</div>
                              <div className="text-sm text-muted-foreground">File Hashes</div>
                            </div>
                          </div>
                          <Separator />
                          <div>
                            <h4 className="text-sm font-medium mb-2">Recent IOCs</h4>
                            <div className="space-y-2">
                              {[
                                { type: "IP", value: "203.0.113.45", threat: "Botnet C&C" },
                                { type: "Domain", value: "malicious-site.com", threat: "Phishing" },
                                { type: "Hash", value: "a1b2c3d4e5f6...", threat: "Malware" },
                              ].map((ioc, index) => (
                                <div key={index} className="flex items-center justify-between text-sm">
                                  <div className="flex items-center gap-2">
                                    <Badge variant="outline" className="text-xs">
                                      {ioc.type}
                                    </Badge>
                                    <code className="text-xs">{ioc.value}</code>
                                  </div>
                                  <span className="text-muted-foreground">{ioc.threat}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  <Card>
                    <CardHeader>
                      <CardTitle>Threat Hunting</CardTitle>
                      <CardDescription>Proactive threat detection and analysis</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <div className="lg:col-span-2">
                          <div className="space-y-4">
                            <div>
                              <Label>Hunt Query</Label>
                              <Textarea
                                placeholder="Enter your threat hunting query (e.g., source_ip in threat_intel AND protocol = 'HTTP')"
                                className="mt-1 font-mono text-sm"
                                rows={3}
                              />
                            </div>
                            <div className="flex gap-2">
                              <Button>
                                <Search className="mr-2 h-4 w-4" />
                                Execute Hunt
                              </Button>
                              <Button variant="outline">
                                <Download className="mr-2 h-4 w-4" />
                                Save Query
                              </Button>
                            </div>
                          </div>
                        </div>
                        <div>
                          <h4 className="text-sm font-medium mb-3">Saved Hunts</h4>
                          <div className="space-y-2">
                            {[
                              "Lateral Movement Detection",
                              "Data Exfiltration Patterns",
                              "Privilege Escalation",
                              "Command & Control Traffic",
                            ].map((hunt, index) => (
                              <Button
                                key={index}
                                variant="outline"
                                size="sm"
                                className="w-full justify-start text-xs bg-transparent"
                              >
                                <Target className="mr-2 h-3 w-3" />
                                {hunt}
                              </Button>
                            ))}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* New Reports Tab */}
              {activeTab === "reports" && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>Generate Report</CardTitle>
                        <CardDescription>Create custom security reports</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div>
                            <Label>Report Type</Label>
                            <Select>
                              <SelectTrigger>
                                <SelectValue placeholder="Select report type" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="security-summary">Security Summary</SelectItem>
                                <SelectItem value="incident-report">Incident Report</SelectItem>
                                <SelectItem value="compliance">Compliance Report</SelectItem>
                                <SelectItem value="threat-analysis">Threat Analysis</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <Label>Time Range</Label>
                            <Select>
                              <SelectTrigger>
                                <SelectValue placeholder="Select time range" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="24h">Last 24 Hours</SelectItem>
                                <SelectItem value="7d">Last 7 Days</SelectItem>
                                <SelectItem value="30d">Last 30 Days</SelectItem>
                                <SelectItem value="custom">Custom Range</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <Label>Format</Label>
                            <div className="flex gap-2 mt-2">
                              <Button variant="outline" size="sm">
                                <FileText className="mr-2 h-4 w-4" />
                                PDF
                              </Button>
                              <Button variant="outline" size="sm">
                                <Download className="mr-2 h-4 w-4" />
                                CSV
                              </Button>
                              <Button variant="outline" size="sm">
                                <Globe className="mr-2 h-4 w-4" />
                                HTML
                              </Button>
                            </div>
                          </div>
                          <Button className="w-full">Generate Report</Button>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Scheduled Reports</CardTitle>
                        <CardDescription>Automated report generation</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {[
                            { name: "Daily Security Summary", schedule: "Daily at 9:00 AM", status: "active" },
                            { name: "Weekly Threat Report", schedule: "Mondays at 8:00 AM", status: "active" },
                            { name: "Monthly Compliance", schedule: "1st of month", status: "paused" },
                          ].map((report, index) => (
                            <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                              <div>
                                <p className="font-medium">{report.name}</p>
                                <p className="text-sm text-muted-foreground">{report.schedule}</p>
                              </div>
                              <div className="flex items-center gap-2">
                                <Badge variant={report.status === "active" ? "default" : "secondary"}>
                                  {report.status}
                                </Badge>
                                <Button variant="outline" size="sm">
                                  <Settings className="h-4 w-4" />
                                </Button>
                              </div>
                            </div>
                          ))}
                        </div>
                        <Button variant="outline" className="w-full mt-4 bg-transparent">
                          <Plus className="mr-2 h-4 w-4" />
                          Add Scheduled Report
                        </Button>
                      </CardContent>
                    </Card>
                  </div>

                  <Card>
                    <CardHeader>
                      <CardTitle>Recent Reports</CardTitle>
                      <CardDescription>Previously generated reports</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead>Report Name</TableHead>
                            <TableHead>Type</TableHead>
                            <TableHead>Generated</TableHead>
                            <TableHead>Size</TableHead>
                            <TableHead className="text-right">Actions</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {[
                            {
                              name: "Security Summary - Jan 2024",
                              type: "Security Summary",
                              date: "2 hours ago",
                              size: "2.4 MB",
                            },
                            {
                              name: "Incident Report - Alert #1234",
                              type: "Incident Report",
                              date: "1 day ago",
                              size: "856 KB",
                            },
                            {
                              name: "Weekly Threat Analysis",
                              type: "Threat Analysis",
                              date: "3 days ago",
                              size: "1.2 MB",
                            },
                          ].map((report, index) => (
                            <TableRow key={index}>
                              <TableCell className="font-medium">{report.name}</TableCell>
                              <TableCell>
                                <Badge variant="outline">{report.type}</Badge>
                              </TableCell>
                              <TableCell>{report.date}</TableCell>
                              <TableCell>{report.size}</TableCell>
                              <TableCell className="text-right">
                                <div className="flex justify-end gap-1">
                                  <Button variant="outline" size="sm">
                                    <Eye className="h-4 w-4" />
                                  </Button>
                                  <Button variant="outline" size="sm">
                                    <Download className="h-4 w-4" />
                                  </Button>
                                </div>
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </CardContent>
                  </Card>
                </div>
              )}

              {/* Enhanced System Status */}
              {activeTab === "system" && (
                <div className="space-y-6">
                  {/* System Health Overview */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">CPU Usage</CardTitle>
                        <Cpu className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{systemHealth.cpuUsage}%</div>
                        <Progress value={systemHealth.cpuUsage} className="mt-2" />
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Memory</CardTitle>
                        <Activity className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{systemHealth.memoryUsage}%</div>
                        <Progress value={systemHealth.memoryUsage} className="mt-2" />
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Disk Usage</CardTitle>
                        <HardDrive className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{systemHealth.diskUsage}%</div>
                        <Progress value={systemHealth.diskUsage} className="mt-2" />
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                        <CardTitle className="text-sm font-medium">Network</CardTitle>
                        <Wifi className="h-4 w-4 text-muted-foreground" />
                      </CardHeader>
                      <CardContent>
                        <div className="text-2xl font-bold">{systemHealth.networkUtilization}%</div>
                        <Progress value={systemHealth.networkUtilization} className="mt-2" />
                      </CardContent>
                    </Card>
                  </div>

                  {/* Performance Charts */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>System Performance</CardTitle>
                        <CardDescription>Resource utilization over time</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <ResponsiveContainer width="100%" height={300}>
                          <LineChart data={trafficData.slice(-20)}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="time" />
                            <YAxis />
                            <RechartsTooltip />
                            <Legend />
                            <Line type="monotone" dataKey="bandwidth" stroke="#8884d8" name="Bandwidth %" />
                          </LineChart>
                        </ResponsiveContainer>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Detection Performance</CardTitle>
                        <CardDescription>ML model accuracy metrics</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div>
                            <div className="flex justify-between mb-2">
                              <span>Detection Rate</span>
                              <span>{systemHealth.detectionRate}%</span>
                            </div>
                            <Progress value={systemHealth.detectionRate} />
                          </div>
                          <div>
                            <div className="flex justify-between mb-2">
                              <span>False Positive Rate</span>
                              <span>{systemHealth.falsePositiveRate}%</span>
                            </div>
                            <Progress value={systemHealth.falsePositiveRate} />
                          </div>
                          <div>
                            <div className="flex justify-between mb-2">
                              <span>Model Confidence</span>
                              <span>87%</span>
                            </div>
                            <Progress value={87} />
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  {/* System Configuration */}
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <Card>
                      <CardHeader>
                        <CardTitle>System Configuration</CardTitle>
                        <CardDescription>Core system settings and preferences</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-6">
                          <div>
                            <Label htmlFor="interface">Network Interface</Label>
                            <Select>
                              <SelectTrigger>
                                <SelectValue placeholder="Select interface" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="eth0">eth0 - Primary Interface</SelectItem>
                                <SelectItem value="eth1">eth1 - Secondary Interface</SelectItem>
                                <SelectItem value="wlan0">wlan0 - Wireless Interface</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>

                          <div>
                            <Label>Detection Thresholds</Label>
                            <div className="grid grid-cols-2 gap-4 mt-2">
                              <div>
                                <Label htmlFor="anomaly-threshold">Anomaly Threshold</Label>
                                <div className="flex items-center gap-2 mt-1">
                                  <Slider defaultValue={[85]} max={100} step={1} className="flex-1" />
                                  <span className="text-sm font-medium w-12">85%</span>
                                </div>
                              </div>
                              <div>
                                <Label htmlFor="alert-threshold">Alert Threshold</Label>
                                <div className="flex items-center gap-2 mt-1">
                                  <Slider defaultValue={[75]} max={100} step={1} className="flex-1" />
                                  <span className="text-sm font-medium w-12">75%</span>
                                </div>
                              </div>
                            </div>
                          </div>

                          <div>
                            <Label>Notification Preferences</Label>
                            <div className="space-y-3 mt-2">
                              <div className="flex items-center justify-between">
                                <Label htmlFor="email-alerts">Email Alerts</Label>
                                <Switch id="email-alerts" defaultChecked />
                              </div>
                              <div className="flex items-center justify-between">
                                <Label htmlFor="sms-critical">SMS for Critical Alerts</Label>
                                <Switch id="sms-critical" defaultChecked />
                              </div>
                              <div className="flex items-center justify-between">
                                <Label htmlFor="sound-notifications">Sound Notifications</Label>
                                <Switch id="sound-notifications" />
                              </div>
                              <div className="flex items-center justify-between">
                                <Label htmlFor="slack-integration">Slack Integration</Label>
                                <Switch id="slack-integration" />
                              </div>
                            </div>
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle>Model Management</CardTitle>
                        <CardDescription>ML model configuration and training</CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-6">
                          <div>
                            <div className="flex items-center justify-between mb-4">
                              <div>
                                <h4 className="font-medium">Current Model</h4>
                                <p className="text-sm text-muted-foreground">Version 2.1.3</p>
                              </div>
                              <Badge variant="default">Active</Badge>
                            </div>
                            <div className="space-y-2 text-sm">
                              <div className="flex justify-between">
                                <span>Last Updated:</span>
                                <span>2 days ago</span>
                              </div>
                              <div className="flex justify-between">
                                <span>Training Data:</span>
                                <span>2.4M samples</span>
                              </div>
                              <div className="flex justify-between">
                                <span>Accuracy:</span>
                                <span>97.3%</span>
                              </div>
                            </div>
                          </div>

                          <Separator />

                          <div>
                            <Label>Confidence Threshold</Label>
                            <div className="flex items-center gap-2 mt-2">
                              <Slider defaultValue={[85]} max={100} step={1} className="flex-1" />
                              <span className="text-sm font-medium w-12">85%</span>
                            </div>
                            <p className="text-xs text-muted-foreground mt-1">
                              Lower values increase sensitivity but may cause more false positives
                            </p>
                          </div>

                          <div className="space-y-2">
                            <Button className="w-full">
                              <RotateCcw className="mr-2 h-4 w-4" />
                              Retrain Model
                            </Button>
                            <Button variant="outline" className="w-full bg-transparent">
                              <Download className="mr-2 h-4 w-4" />
                              Export Model
                            </Button>
                            <Button variant="outline" className="w-full bg-transparent">
                              <Upload className="mr-2 h-4 w-4" />
                              Import Model
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>

                  {/* System Logs */}
                  <Card>
                    <CardHeader>
                      <div className="flex items-center justify-between">
                        <div>
                          <CardTitle>System Logs</CardTitle>
                          <CardDescription>Recent system events and diagnostics</CardDescription>
                        </div>
                        <div className="flex items-center gap-2">
                          <Button variant="outline" size="sm">
                            <RefreshCw className="mr-2 h-4 w-4" />
                            Refresh
                          </Button>
                          <Button variant="outline" size="sm">
                            <Download className="mr-2 h-4 w-4" />
                            Export Logs
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <ScrollArea className="h-64">
                        <div className="space-y-1 font-mono text-sm">
                          {[
                            {
                              time: "2024-01-15 14:32:15",
                              level: "INFO",
                              message: "NIDS service started successfully",
                            },
                            {
                              time: "2024-01-15 14:32:16",
                              level: "INFO",
                              message: "Network interface eth0 initialized",
                            },
                            { time: "2024-01-15 14:32:17", level: "INFO", message: "ML model v2.1.3 loaded" },
                            { time: "2024-01-15 14:35:22", level: "WARN", message: "High CPU usage detected (89%)" },
                            {
                              time: "2024-01-15 14:36:45",
                              level: "INFO",
                              message: "Alert #1234 generated - SQL Injection detected",
                            },
                            {
                              time: "2024-01-15 14:37:12",
                              level: "INFO",
                              message: "Threat intelligence feeds updated",
                            },
                            {
                              time: "2024-01-15 14:38:33",
                              level: "ERROR",
                              message: "Failed to connect to external threat feed",
                            },
                            {
                              time: "2024-01-15 14:39:01",
                              level: "INFO",
                              message: "Connection to threat feed restored",
                            },
                          ].map((log, index) => (
                            <div key={index} className="flex gap-4 py-1">
                              <span className="text-muted-foreground">{log.time}</span>
                              <Badge
                                variant={
                                  log.level === "ERROR" ? "destructive" : log.level === "WARN" ? "default" : "secondary"
                                }
                                className="text-xs"
                              >
                                {log.level}
                              </Badge>
                              <span className="flex-1">{log.message}</span>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </CardContent>
                  </Card>
                </div>
              )}
            </main>
          </div>
        </div>
      </div>
    </TooltipProvider>
  )
}
