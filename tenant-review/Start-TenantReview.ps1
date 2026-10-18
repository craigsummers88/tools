param([switch]$NoRelaunch)

if (-not $NoRelaunch -and [Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    $exe = (Get-Process -Id $PID).Path
    Start-Process -FilePath $exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', ('"{0}"' -f $PSCommandPath), '-NoRelaunch')
    return
}

Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
try {
    if (-not ('TR.AppId' -as [type])) {
        Add-Type -Namespace TR -Name AppId -MemberDefinition '[System.Runtime.InteropServices.DllImport("shell32.dll", SetLastError = true)] public static extern int SetCurrentProcessExplicitAppUserModelID([System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string appId);'
    }
    [void][TR.AppId]::SetCurrentProcessExplicitAppUserModelID('TenantReview.App')
}
catch { }

trap {
    [System.Windows.MessageBox]::Show(('Unexpected error: {0}' -f $_.Exception.Message), 'Tenant Review', 'OK', 'Error') | Out-Null
    break
}

$root = Split-Path -Parent $PSCommandPath
$modulePath = Join-Path $root 'Module\TenantReview.psm1'
$configPath = Join-Path $root 'config.json'
$stateFolder = Join-Path $env:APPDATA 'TenantReview'
$statePath = Join-Path $stateFolder 'gui-settings.json'

function Show-TRMessage {
    param([string]$Text, [string]$Title = 'Tenant Review', [string]$Icon = 'Information', [string]$Buttons = 'OK')
    [System.Windows.MessageBox]::Show($Text, $Title, $Buttons, $Icon)
}

try {
    $config = $null
    if (Test-Path -LiteralPath $configPath) { $config = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    $guiState = $null
    if (Test-Path -LiteralPath $statePath) { try { $guiState = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $guiState = $null } }
}
catch {
    Show-TRMessage ("Could not read config.json: " + $_.Exception.Message) -Icon Error | Out-Null
    return
}

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Tenant Review" Width="1200" Height="860" MinWidth="1000" MinHeight="660"
        WindowStartupLocation="CenterScreen" Background="#EEF2F5" FontFamily="Arial" FontSize="13" Foreground="#1D2730">
  <Window.Resources>
    <Style x:Key="Card" TargetType="Border">
      <Setter Property="Background" Value="White"/>
      <Setter Property="BorderBrush" Value="#DCE3E9"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="CornerRadius" Value="10"/>
      <Setter Property="Padding" Value="18,16"/>
      <Setter Property="Margin" Value="0,0,0,12"/>
    </Style>
    <Style x:Key="StepBadge" TargetType="Border">
      <Setter Property="Width" Value="28"/>
      <Setter Property="Height" Value="28"/>
      <Setter Property="CornerRadius" Value="14"/>
      <Setter Property="Background" Value="#0F4761"/>
      <Setter Property="Margin" Value="0,0,12,0"/>
      <Setter Property="VerticalAlignment" Value="Top"/>
    </Style>
    <Style x:Key="StepNumber" TargetType="TextBlock">
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="FontSize" Value="13"/>
      <Setter Property="HorizontalAlignment" Value="Center"/>
      <Setter Property="VerticalAlignment" Value="Center"/>
    </Style>
    <Style x:Key="CardTitle" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#0F4761"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="FontSize" Value="15"/>
    </Style>
    <Style x:Key="Hint" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#5F6B76"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="0,2,0,0"/>
    </Style>
    <Style x:Key="FieldLabel" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#3D4A55"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Margin" Value="0,12,0,5"/>
    </Style>
    <Style x:Key="Group" TargetType="TextBlock">
      <Setter Property="Foreground" Value="#5F6B76"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="FontSize" Value="11"/>
      <Setter Property="Margin" Value="0,14,0,4"/>
    </Style>
    <Style TargetType="TextBox">
      <Setter Property="Padding" Value="8,7"/>
      <Setter Property="BorderBrush" Value="#C5D0D8"/>
      <Setter Property="BorderThickness" Value="1"/>
      <Setter Property="Background" Value="White"/>
      <Setter Property="Foreground" Value="#1D2730"/>
      <Setter Property="VerticalContentAlignment" Value="Center"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" VerticalAlignment="{TemplateBinding VerticalContentAlignment}" Focusable="False" HorizontalScrollBarVisibility="Hidden" VerticalScrollBarVisibility="Hidden"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#7F97A8"/></Trigger>
              <Trigger Property="IsKeyboardFocused" Value="True"><Setter TargetName="bd" Property="BorderBrush" Value="#0F4761"/><Setter TargetName="bd" Property="BorderThickness" Value="1.5"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="bd" Property="Opacity" Value="0.6"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="LogBox" TargetType="TextBox">
      <Setter Property="Background" Value="#0E2836"/>
      <Setter Property="Foreground" Value="#D3DFE7"/>
      <Setter Property="FontFamily" Value="Consolas"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="Padding" Value="12,10"/>
      <Setter Property="IsReadOnly" Value="True"/>
      <Setter Property="TextWrapping" Value="Wrap"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="TextBox">
            <Border Background="{TemplateBinding Background}" CornerRadius="8">
              <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" Focusable="False" HorizontalScrollBarVisibility="Disabled" VerticalScrollBarVisibility="Auto"/>
            </Border>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="CheckBox">
      <Setter Property="Margin" Value="0,4,0,4"/>
      <Setter Property="Foreground" Value="#1D2730"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="CheckBox">
            <Grid Background="Transparent">
              <Grid.ColumnDefinitions>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
              </Grid.ColumnDefinitions>
              <Border x:Name="box" Width="18" Height="18" CornerRadius="4" BorderThickness="1.5" BorderBrush="#9AA9B5" Background="White" VerticalAlignment="Top">
                <Path x:Name="tick" Data="M3.5,8.5 L6.8,11.8 L12.5,5.2" Stroke="White" StrokeThickness="2" StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round" Visibility="Collapsed"/>
              </Border>
              <ContentPresenter Grid.Column="1" Margin="10,1,0,0" VerticalAlignment="Top" RecognizesAccessKey="True"/>
            </Grid>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="box" Property="BorderBrush" Value="#0F4761"/></Trigger>
              <Trigger Property="IsChecked" Value="True"><Setter TargetName="box" Property="Background" Value="#0F4761"/><Setter TargetName="box" Property="BorderBrush" Value="#0F4761"/><Setter TargetName="tick" Property="Visibility" Value="Visible"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style TargetType="ProgressBar">
      <Setter Property="Height" Value="10"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="ProgressBar">
            <Grid>
              <Border x:Name="PART_Track" CornerRadius="5" Background="#E3E9EE"/>
              <Border x:Name="PART_Indicator" CornerRadius="5" Background="#0F4761" HorizontalAlignment="Left"/>
            </Grid>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Primary" TargetType="Button">
      <Setter Property="Background" Value="#0F4761"/>
      <Setter Property="Foreground" Value="White"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Padding" Value="14,9"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="7" Padding="{TemplateBinding Padding}" BorderBrush="#0F4761" BorderThickness="1">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#1B5E7E"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#0A3447"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Secondary" TargetType="Button" BasedOn="{StaticResource Primary}">
      <Setter Property="Background" Value="White"/>
      <Setter Property="Foreground" Value="#0F4761"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="{TemplateBinding Background}" CornerRadius="7" Padding="{TemplateBinding Padding}" BorderBrush="#9FB3C1" BorderThickness="1">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#EAF0F4"/><Setter TargetName="b" Property="BorderBrush" Value="#0F4761"/></Trigger>
              <Trigger Property="IsPressed" Value="True"><Setter TargetName="b" Property="Background" Value="#DCE6ED"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Link" TargetType="Button">
      <Setter Property="Foreground" Value="#1B5E7E"/>
      <Setter Property="FontSize" Value="12"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="Button">
            <Border x:Name="b" Background="Transparent" CornerRadius="4" Padding="6,3">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#EAF0F4"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.4"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
    <Style x:Key="Toggle" TargetType="RadioButton">
      <Setter Property="Foreground" Value="#0F4761"/>
      <Setter Property="FontWeight" Value="Bold"/>
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="b" Background="Transparent" CornerRadius="6" Padding="8,8">
              <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsMouseOver" Value="True"><Setter TargetName="b" Property="Background" Value="#DCE6ED"/></Trigger>
              <Trigger Property="IsChecked" Value="True"><Setter TargetName="b" Property="Background" Value="#0F4761"/><Setter Property="Foreground" Value="White"/></Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter TargetName="b" Property="Opacity" Value="0.45"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="Auto"/>
      <RowDefinition Height="*"/>
    </Grid.RowDefinitions>
    <Border Grid.Row="0" Background="White" BorderBrush="#0F4761" BorderThickness="0,0,0,4" Padding="22,10">
      <DockPanel>
        <Border DockPanel.Dock="Right" Background="#E7F4E8" CornerRadius="13" Padding="12,5" VerticalAlignment="Center" ToolTip="The review only reads settings. It never changes anything in the client's environment, apart from removing the review app when you ask it to.">
          <TextBlock Text="Read-only review" Foreground="#2E7D32" FontWeight="Bold" FontSize="12"/>
        </Border>
        <ContentControl x:Name="LogoHost" DockPanel.Dock="Left" Height="54" VerticalAlignment="Center" Margin="0,0,18,0" Visibility="Collapsed"/>
        <Border x:Name="LogoFallback" DockPanel.Dock="Left" BorderBrush="#0F4761" BorderThickness="2" CornerRadius="5" Width="42" Height="42" Margin="0,0,12,0">
          <TextBlock Text="TR" Foreground="#0F4761" FontWeight="Bold" HorizontalAlignment="Center" VerticalAlignment="Center"/>
        </Border>
        <Border DockPanel.Dock="Left" Width="1" Background="#D9E1E7" Margin="0,6,18,6"/>
        <StackPanel VerticalAlignment="Center">
          <TextBlock x:Name="TxtProduct" Text="Microsoft 365 Tenant Review" Foreground="#0F4761" FontSize="19" FontWeight="Bold"/>
          <TextBlock x:Name="TxtVersion" Text="Read-only review" Foreground="#5F6B76" FontSize="12" Margin="0,2,0,0"/>
        </StackPanel>
      </DockPanel>
    </Border>
    <Grid Grid.Row="1" Margin="18,16,18,18">
      <Grid.ColumnDefinitions>
        <ColumnDefinition Width="420"/>
        <ColumnDefinition Width="16"/>
        <ColumnDefinition Width="*"/>
      </Grid.ColumnDefinitions>
      <ScrollViewer Grid.Column="0" VerticalScrollBarVisibility="Auto" Padding="0,0,6,0">
        <StackPanel>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,14">
                <Border Style="{StaticResource StepBadge}"><TextBlock Style="{StaticResource StepNumber}" Text="1"/></Border>
                <StackPanel>
                  <TextBlock Style="{StaticResource CardTitle}" Text="Client"/>
                  <TextBlock Style="{StaticResource Hint}" Text="Choose the platform, then sign in to the client."/>
                </StackPanel>
              </DockPanel>
              <Border Background="#EEF2F5" CornerRadius="8" Padding="3">
                <Grid>
                  <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="4"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                  <RadioButton x:Name="RbMicrosoft" Grid.Column="0" GroupName="Platform" Style="{StaticResource Toggle}" Content="Microsoft 365" IsChecked="True"/>
                  <RadioButton x:Name="RbGoogle" Grid.Column="2" GroupName="Platform" Style="{StaticResource Toggle}" Content="Google Workspace"/>
                </Grid>
              </Border>
              <TextBlock Style="{StaticResource FieldLabel}" Text="Client name (shown on the report)"/>
              <TextBox x:Name="TxtClient"/>
              <TextBlock x:Name="LblTenant" Style="{StaticResource FieldLabel}" Text="Tenant (onmicrosoft.com domain, verified domain or tenant ID)"/>
              <TextBox x:Name="TxtTenant"/>
              <Grid Margin="0,14,0,0">
                <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="8"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
                <Button x:Name="BtnConsent" Grid.Column="0" Style="{StaticResource Secondary}" Content="Grant consent" ToolTip="First time only for each client tenant. Needs Cloud Application Administrator (GDAP) or the client's Global Administrator."/>
                <Button x:Name="BtnSignIn" Grid.Column="2" Style="{StaticResource Primary}" Content="Sign in"/>
              </Grid>
              <Border x:Name="BdSignedIn" Background="#EEF2F5" CornerRadius="8" Padding="12,10" Margin="0,12,0,0">
                <TextBlock x:Name="TxtSignedIn" TextWrapping="Wrap" Foreground="#5F6B76" Text="Not signed in."/>
              </Border>
              <Button x:Name="BtnCopyLink" Style="{StaticResource Secondary}" Content="Copy sign-in link" Margin="0,8,0,0" Visibility="Collapsed" ToolTip="Paste into a different browser profile or a private window if the wrong account opens."/>
              <Button x:Name="BtnRemoveApp" Style="{StaticResource Link}" Content="Remove the review app from this tenant" Margin="-6,8,0,0" HorizontalAlignment="Left" ToolTip="Deletes the review app and its permissions from the client tenant. You will need to Grant consent again before the next review."/>
              <Expander Header="Advanced" Margin="0,8,0,0" Foreground="#5F6B76">
                <StackPanel Margin="0,4,0,0">
                  <StackPanel x:Name="PnlMsAdvanced">
                    <TextBlock Style="{StaticResource FieldLabel}" Text="App (client) ID of the review app"/>
                    <TextBox x:Name="TxtClientId"/>
                  </StackPanel>
                  <StackPanel x:Name="PnlGoogleAdvanced" Visibility="Collapsed">
                    <TextBlock Style="{StaticResource FieldLabel}" Text="Google OAuth client ID (Desktop app) of the review app"/>
                    <TextBox x:Name="TxtGoogleClientId"/>
                    <TextBlock Style="{StaticResource Hint}" Text="The client secret is read from GoogleClientSecret in config.json."/>
                  </StackPanel>
                  <Button x:Name="BtnShortcut" Style="{StaticResource Secondary}" Content="Create desktop shortcut" Margin="0,12,0,0" HorizontalAlignment="Left" Padding="12,6"/>
                </StackPanel>
              </Expander>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,6">
                <Border Style="{StaticResource StepBadge}"><TextBlock Style="{StaticResource StepNumber}" Text="2"/></Border>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Top">
                  <Button x:Name="BtnAreasDefault" Style="{StaticResource Link}" Content="Defaults" ToolTip="Tick the standard set of areas."/>
                  <Button x:Name="BtnAreasNone" Style="{StaticResource Link}" Content="None" ToolTip="Untick every optional area."/>
                </StackPanel>
                <StackPanel>
                  <TextBlock Style="{StaticResource CardTitle}" Text="Review areas"/>
                  <TextBlock Style="{StaticResource Hint}" Text="Everything is read-only. Untick anything you do not need."/>
                </StackPanel>
              </DockPanel>
              <StackPanel x:Name="PnlMsAreas">
                <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,2" Text="Always included: identity, access, privileged roles and licensing."/>
                <TextBlock Style="{StaticResource Group}" Text="MICROSOFT 365"/>
                <CheckBox x:Name="ChkApplications" Content="Applications and consents" IsChecked="True"/>
                <CheckBox x:Name="ChkExchange" Content="Exchange Online and email security" IsChecked="True"/>
                <CheckBox x:Name="ChkDns" Content="Email DNS (SPF, DKIM, DMARC)" IsChecked="True"/>
                <CheckBox x:Name="ChkCollaboration" Content="SharePoint, OneDrive and Teams" IsChecked="True"/>
                <CheckBox x:Name="ChkIntune" Content="Intune and devices" IsChecked="True"/>
                <CheckBox x:Name="ChkDefender" Content="Microsoft Defender XDR (devices, vulnerabilities, incidents)" IsChecked="True"/>
                <CheckBox x:Name="ChkPurview" Content="Microsoft Purview (DLP, retention, labels, alerts)" IsChecked="True"/>
                <CheckBox x:Name="ChkSecureScore" Content="Microsoft Secure Score" IsChecked="True"/>
                <CheckBox x:Name="ChkOpportunities" Content="Licensed but not used (opportunities)" IsChecked="True"/>
                <TextBlock Style="{StaticResource Group}" Text="AZURE"/>
                <CheckBox x:Name="ChkAzure" IsChecked="True" ToolTip="Reads Azure subscriptions, resources, Defender for Cloud and Advisor with your Azure roles. You are asked once to approve Azure read access.">
                  <TextBlock TextWrapping="Wrap" Text="Azure subscriptions and resources (asks you to approve Azure read access)"/>
                </CheckBox>
                <TextBlock Style="{StaticResource Group}" Text="BENCHMARKS"/>
                <CheckBox x:Name="ChkBenchmarks" Content="CIS Microsoft 365 v7.0.0 and CISA SCuBA baselines" IsChecked="True"/>
                <CheckBox x:Name="ChkServiceSettings" IsChecked="True" ToolTip="Reads Teams policies, SharePoint tenant settings, Power BI tenant settings and Power Platform settings. You are asked once to approve read access to these services.">
                  <TextBlock TextWrapping="Wrap" Text="Teams, SharePoint, Power BI and Power Platform settings (asks you to approve extra read access)"/>
                </CheckBox>
                <TextBlock Style="{StaticResource Group}" Text="PERMISSIONS"/>
                <CheckBox x:Name="ChkMailboxPermissions" Content="Mailbox permissions (Full Access, Send As)" IsChecked="True"/>
                <CheckBox x:Name="ChkGroupMembership" Content="Group, Team and site membership" IsChecked="True"/>
                <CheckBox x:Name="ChkSharingAudit" Content="Sharing links from audit log (adds 5 to 20 minutes)" IsChecked="False"/>
              </StackPanel>
              <StackPanel x:Name="PnlGoogleAreas" Visibility="Collapsed">
                <TextBlock Style="{StaticResource Hint}" Margin="0,4,0,2" Text="Always included: users, sign-in, administrators and licensing."/>
                <TextBlock Style="{StaticResource Group}" Text="GOOGLE WORKSPACE"/>
                <CheckBox x:Name="GChkApplications" Content="Third-party apps and API access" IsChecked="True"/>
                <CheckBox x:Name="GChkGmail" Content="Gmail security settings" IsChecked="True"/>
                <CheckBox x:Name="GChkDns" Content="Email DNS (MX, SPF, DKIM, DMARC)" IsChecked="True"/>
                <CheckBox x:Name="GChkDrive" Content="Drive and Docs sharing" IsChecked="True"/>
                <CheckBox x:Name="GChkCollaboration" Content="Calendar, Chat, Meet, Groups and Sites" IsChecked="True"/>
                <CheckBox x:Name="GChkDevices" Content="Endpoint management (mobile, Windows, ChromeOS)" IsChecked="True"/>
                <CheckBox x:Name="GChkSecurity" Content="Alert Center, alert rules and data protection" IsChecked="True"/>
                <CheckBox x:Name="GChkOpportunities" Content="Licensed but not used (opportunities)" IsChecked="True"/>
                <TextBlock Style="{StaticResource Group}" Text="BENCHMARKS"/>
                <CheckBox x:Name="GChkBenchmarks" Content="CIS Google Workspace v1.4.0 and CISA SCuBA baselines" IsChecked="True"/>
                <TextBlock Style="{StaticResource Group}" Text="PERMISSIONS"/>
                <CheckBox x:Name="GChkGroupMembership" Content="Group membership" IsChecked="True"/>
                <CheckBox x:Name="GChkDriveSharing" Content="Drive sharing activity from the audit log (30 days)" IsChecked="False"/>
              </StackPanel>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,10">
                <Border Style="{StaticResource StepBadge}"><TextBlock Style="{StaticResource StepNumber}" Text="3"/></Border>
                <Border DockPanel.Dock="Right" Background="#EEF2F5" CornerRadius="10" Padding="8,3" VerticalAlignment="Top">
                  <TextBlock Text="Optional" Foreground="#5F6B76" FontSize="11" FontWeight="Bold"/>
                </Border>
                <StackPanel>
                  <TextBlock Style="{StaticResource CardTitle}" Text="Servers"/>
                  <TextBlock Style="{StaticResource Hint}" Text="Add Windows, Linux and VMware servers from the server collectors."/>
                </StackPanel>
              </DockPanel>
              <CheckBox x:Name="ChkServers" IsChecked="False">
                <TextBlock TextWrapping="Wrap" Text="Include server data from the server collectors"/>
              </CheckBox>
              <TextBlock Style="{StaticResource FieldLabel}" Text="Server data folder"/>
              <DockPanel>
                <Button x:Name="BtnServerBrowse" DockPanel.Dock="Right" Style="{StaticResource Secondary}" Content="Browse" Margin="8,0,0,0" Padding="14,6"/>
                <TextBox x:Name="TxtServerData"/>
              </DockPanel>
              <TextBlock Style="{StaticResource Hint}" Margin="0,8,0,0" Text="Run the scripts in the Collectors folder first: Get-ServerReviewData.ps1 on each Windows server (locally or through the RMM), Invoke-ServerReviewCollection.ps1 to collect over WinRM, server-review-collect.sh on Linux and Get-VMwareReviewData.ps1 for vCenter. Then choose the folder that holds the .server-review.json files."/>
            </StackPanel>
          </Border>
          <Border Style="{StaticResource Card}">
            <StackPanel>
              <DockPanel Margin="0,0,0,4">
                <Border Style="{StaticResource StepBadge}"><TextBlock Style="{StaticResource StepNumber}" Text="4"/></Border>
                <StackPanel>
                  <TextBlock Style="{StaticResource CardTitle}" Text="Output"/>
                  <TextBlock Style="{StaticResource Hint}" Text="The report, both PDFs and the CSV files are saved here."/>
                </StackPanel>
              </DockPanel>
              <TextBlock Style="{StaticResource FieldLabel}" Text="Reports folder"/>
              <DockPanel>
                <Button x:Name="BtnBrowse" DockPanel.Dock="Right" Style="{StaticResource Secondary}" Content="Browse" Margin="8,0,0,0" Padding="14,6"/>
                <TextBox x:Name="TxtOutput"/>
              </DockPanel>
              <CheckBox x:Name="ChkOpen" Content="Open the report when the review finishes" IsChecked="True" Margin="0,12,0,4"/>
              <CheckBox x:Name="ChkRemoveApp" IsChecked="False">
                <TextBlock x:Name="TxtRemoveApp" TextWrapping="Wrap" Text="Remove the review app from the client tenant when the review finishes (you sign in once more to approve it)"/>
              </CheckBox>
            </StackPanel>
          </Border>
          <Grid Margin="0,2,0,4">
            <Grid.ColumnDefinitions><ColumnDefinition Width="2*"/><ColumnDefinition Width="8"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
            <Button x:Name="BtnRun" Grid.Column="0" Style="{StaticResource Primary}" Content="Run review" Padding="14,13" FontSize="15" IsEnabled="False"/>
            <Button x:Name="BtnCancel" Grid.Column="2" Style="{StaticResource Secondary}" Content="Cancel" IsEnabled="False"/>
          </Grid>
        </StackPanel>
      </ScrollViewer>
      <Border Grid.Column="2" Style="{StaticResource Card}" Margin="0">
        <Grid>
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <DockPanel Grid.Row="0" Margin="0,0,0,12">
            <TextBlock x:Name="TxtPercent" DockPanel.Dock="Right" Foreground="#0F4761" FontWeight="Bold" FontSize="15" VerticalAlignment="Center" Text=""/>
            <StackPanel>
              <TextBlock Style="{StaticResource CardTitle}" Text="Progress"/>
              <TextBlock Style="{StaticResource Hint}" Text="Each step is logged below. Failed steps are listed in the report under Collection diagnostics."/>
            </StackPanel>
          </DockPanel>
          <ProgressBar Grid.Row="1" x:Name="PbMain" Minimum="0" Maximum="100"/>
          <Border Grid.Row="2" Background="#F3F6F8" BorderBrush="#E3E9EE" BorderThickness="1" CornerRadius="8" Padding="12,10" Margin="0,12,0,12">
            <TextBlock x:Name="TxtActivity" Foreground="#1D2730" TextWrapping="Wrap" Text="Ready."/>
          </Border>
          <TextBox Grid.Row="3" x:Name="TxtLog" Style="{StaticResource LogBox}"/>
          <StackPanel Grid.Row="4" Margin="0,14,0,0">
            <TextBlock Style="{StaticResource Group}" Margin="0,0,0,8" Text="RESULTS"/>
            <DockPanel>
              <Button x:Name="BtnRebuild" DockPanel.Dock="Right" Style="{StaticResource Link}" Content="Rebuild from saved data" VerticalAlignment="Center" ToolTip="Re-run the checks and regenerate the HTML, PDF and CSV files from a RawData.json file without signing in again."/>
              <WrapPanel>
                <Button x:Name="BtnOpenReport" Style="{StaticResource Primary}" Content="Open report" IsEnabled="False" Margin="0,0,8,8"/>
                <Button x:Name="BtnOpenSummary" Style="{StaticResource Secondary}" Content="Action plan PDF" IsEnabled="False" Margin="0,0,8,8" ToolTip="A short PDF for the client with the executive summary and the action plan."/>
                <Button x:Name="BtnOpenPdf" Style="{StaticResource Secondary}" Content="Full PDF" IsEnabled="False" Margin="0,0,8,8"/>
                <Button x:Name="BtnOpenFolder" Style="{StaticResource Secondary}" Content="Open folder" IsEnabled="False" Margin="0,0,8,8"/>
              </WrapPanel>
            </DockPanel>
          </StackPanel>
        </Grid>
      </Border>
    </Grid>
  </Grid>
</Window>
'@

$window = [Windows.Markup.XamlReader]::Load((New-Object System.Xml.XmlNodeReader $xaml))
$ui = @{}
foreach ($n in 'TxtVersion', 'TxtClient', 'TxtTenant', 'BtnConsent', 'BtnSignIn', 'TxtSignedIn', 'BtnCopyLink', 'TxtClientId', 'ChkApplications', 'ChkExchange', 'ChkDns', 'ChkCollaboration', 'ChkIntune', 'ChkDefender', 'ChkPurview', 'ChkSecureScore', 'ChkAzure', 'ChkOpportunities', 'ChkBenchmarks', 'ChkServiceSettings', 'ChkMailboxPermissions', 'ChkGroupMembership', 'ChkSharingAudit', 'BtnBrowse', 'TxtOutput', 'ChkOpen', 'BtnRun', 'BtnCancel', 'PbMain', 'TxtActivity', 'TxtLog', 'BtnOpenReport', 'BtnOpenPdf', 'BtnOpenFolder', 'BtnRebuild', 'LogoHost', 'LogoFallback', 'BtnShortcut', 'BtnRemoveApp', 'ChkRemoveApp', 'TxtProduct', 'RbMicrosoft', 'RbGoogle', 'LblTenant', 'PnlMsAreas', 'PnlGoogleAreas', 'PnlMsAdvanced', 'PnlGoogleAdvanced', 'TxtGoogleClientId', 'TxtRemoveApp', 'GChkApplications', 'GChkGmail', 'GChkDns', 'GChkDrive', 'GChkCollaboration', 'GChkDevices', 'GChkSecurity', 'GChkOpportunities', 'GChkBenchmarks', 'GChkGroupMembership', 'GChkDriveSharing', 'ChkServers', 'TxtServerData', 'BtnServerBrowse', 'BtnOpenSummary', 'TxtPercent', 'BdSignedIn', 'BtnAreasDefault', 'BtnAreasNone') {
    $ui[$n] = $window.FindName($n)
}
$areaBoxes = [ordered]@{
    Applications       = $ui.ChkApplications
    Exchange           = $ui.ChkExchange
    Dns                = $ui.ChkDns
    Collaboration      = $ui.ChkCollaboration
    Intune             = $ui.ChkIntune
    Defender           = $ui.ChkDefender
    Purview            = $ui.ChkPurview
    SecureScore        = $ui.ChkSecureScore
    Azure              = $ui.ChkAzure
    Opportunities      = $ui.ChkOpportunities
    Benchmarks         = $ui.ChkBenchmarks
    ServiceSettings    = $ui.ChkServiceSettings
    MailboxPermissions = $ui.ChkMailboxPermissions
    GroupMembership    = $ui.ChkGroupMembership
    SharingAudit       = $ui.ChkSharingAudit
}
$googleBoxes = [ordered]@{
    Applications    = $ui.GChkApplications
    Gmail           = $ui.GChkGmail
    Dns             = $ui.GChkDns
    Drive           = $ui.GChkDrive
    Collaboration   = $ui.GChkCollaboration
    Devices         = $ui.GChkDevices
    Security        = $ui.GChkSecurity
    Opportunities   = $ui.GChkOpportunities
    Benchmarks      = $ui.GChkBenchmarks
    GroupMembership = $ui.GChkGroupMembership
    DriveSharing    = $ui.GChkDriveSharing
}
$googleAdminUrl = 'https://admin.google.com/ac/owl/list?tab=configuredApps'

function New-TRLogoElement {
    param([string]$Path, [double]$Height)
    $ext = [IO.Path]::GetExtension($Path).ToLower()
    if ($ext -in @('.png', '.jpg', '.jpeg')) {
        $bmp = New-Object System.Windows.Media.Imaging.BitmapImage
        $bmp.BeginInit()
        $bmp.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $bmp.UriSource = New-Object System.Uri($Path)
        $bmp.EndInit()
        $img = New-Object System.Windows.Controls.Image
        $img.Source = $bmp
        $img.Height = $Height
        return $img
    }
    if ($ext -ne '.svg') { return $null }
    [xml]$svg = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $svgRoot = $svg.DocumentElement
    $box = @(([string]$svgRoot.GetAttribute('viewBox')).Trim() -split '[\s,]+')
    if ($box.Count -ne 4) { return $null }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('<Viewbox xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" Stretch="Uniform" Height="' + [string]$Height + '"><Canvas Width="' + [string][double]$box[2] + '" Height="' + [string][double]$box[3] + '">')
    $count = 0
    foreach ($node in $svgRoot.GetElementsByTagName('path')) {
        $d = [string]$node.GetAttribute('d')
        $fill = [string]$node.GetAttribute('fill')
        if (-not $d -or $fill -eq 'none') { continue }
        if (-not $fill) { $fill = '#000000' }
        $rule = if ([string]$node.GetAttribute('fill-rule') -eq 'evenodd') { 'F0 ' } else { 'F1 ' }
        [void]$sb.Append('<Path Data="' + [Security.SecurityElement]::Escape($rule + $d) + '" Fill="' + [Security.SecurityElement]::Escape($fill) + '"/>')
        $count++
    }
    [void]$sb.Append('</Canvas></Viewbox>')
    if (-not $count) { return $null }
    [Windows.Markup.XamlReader]::Parse($sb.ToString())
}

try {
    $logoSetting = if ($config -and $config.PSObject.Properties['LogoPath'] -and $config.LogoPath) { [Environment]::ExpandEnvironmentVariables([string]$config.LogoPath) } else { Join-Path (Join-Path $root 'Assets') 'logo.svg' }
    if (-not [IO.Path]::IsPathRooted($logoSetting)) { $logoSetting = Join-Path $root $logoSetting }
    if (Test-Path -LiteralPath $logoSetting -PathType Leaf) {
        $logoElement = New-TRLogoElement -Path $logoSetting -Height 54
        if ($logoElement) {
            $ui.LogoHost.Content = $logoElement
            $ui.LogoHost.Visibility = 'Visible'
            $ui.LogoFallback.Visibility = 'Collapsed'
        }
    }
}
catch { }

$iconPath = Join-Path (Join-Path $root 'Assets') 'app-icon.ico'
if (Test-Path -LiteralPath $iconPath -PathType Leaf) {
    try { $window.Icon = [System.Windows.Media.Imaging.BitmapFrame]::Create((New-Object System.Uri($iconPath))) } catch { }
}

$defaultOutput = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'Tenant Reviews'
if ($config -and $config.OutputRoot) { $defaultOutput = [Environment]::ExpandEnvironmentVariables([string]$config.OutputRoot) }
$ui.TxtOutput.Text = $(if ($guiState -and $guiState.OutputRoot) { [string]$guiState.OutputRoot } else { $defaultOutput })
$ui.TxtClientId.Text = $(if ($config -and $config.ClientId) { [string]$config.ClientId } else { '' })
$ui.TxtGoogleClientId.Text = $(if ($config -and $config.PSObject.Properties['GoogleClientId'] -and $config.GoogleClientId) { [string]$config.GoogleClientId } else { '' })
$googleSecret = $(if ($config -and $config.PSObject.Properties['GoogleClientSecret'] -and $config.GoogleClientSecret) { [string]$config.GoogleClientSecret } else { '' })
if ($guiState -and $guiState.PSObject.Properties['RemoveApp']) { $ui.ChkRemoveApp.IsChecked = [bool]$guiState.RemoveApp }
if ($guiState -and $guiState.PSObject.Properties['ServerDataPath']) { $ui.TxtServerData.Text = [string]$guiState.ServerDataPath }
if ($guiState -and $guiState.PSObject.Properties['IncludeServers']) { $ui.ChkServers.IsChecked = [bool]$guiState.IncludeServers }
if ($guiState -and $guiState.Areas) {
    $known = @('Applications', 'Exchange', 'Dns', 'Collaboration', 'Intune', 'SecureScore', 'MailboxPermissions', 'GroupMembership', 'SharingAudit')
    if ($guiState.PSObject.Properties['KnownAreas'] -and $guiState.KnownAreas) { $known = @($guiState.KnownAreas) }
    foreach ($k in $areaBoxes.Keys) {
        if ($known -contains $k) { $areaBoxes[$k].IsChecked = (@($guiState.Areas) -contains $k) }
    }
}
if ($guiState -and $guiState.PSObject.Properties['GoogleAreas'] -and $null -ne $guiState.GoogleAreas) {
    $gKnown = if ($guiState.PSObject.Properties['GoogleKnownAreas'] -and $guiState.GoogleKnownAreas) { @($guiState.GoogleKnownAreas) } else { @($googleBoxes.Keys) }
    foreach ($k in $googleBoxes.Keys) {
        if ($gKnown -contains $k) { $googleBoxes[$k].IsChecked = (@($guiState.GoogleAreas) -contains $k) }
    }
}

$sync = [hashtable]::Synchronized(@{
        Log       = New-Object 'System.Collections.Concurrent.ConcurrentQueue[string]'
        Percent   = 0
        Activity  = ''
        Busy      = $false
        Cancel    = $false
        Done      = $false
        Operation = ''
        AuthUrl   = ''
        Result    = $null
        Error     = $null
    })

$iss = [initialsessionstate]::CreateDefault()
try { $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass } catch { }
$runspace = [runspacefactory]::CreateRunspace($iss)
$runspace.ThreadOptions = 'ReuseThread'
$runspace.Open()
$runspace.SessionStateProxy.SetVariable('sync', $sync)
$init = [powershell]::Create()
$init.Runspace = $runspace
[void]$init.AddScript({
        param($ModulePath, $ConfigPath)
        Import-Module $ModulePath -Force -DisableNameChecking
        Import-TRSettings -Path $ConfigPath | Out-Null
        Set-TRHost -LogSink { param($line, $level) $sync.Log.Enqueue($line) } -ProgressSink { param($p, $a) $sync.Percent = $p; $sync.Activity = $a } -CancelCheck { [bool]$sync.Cancel } -AuthUrlSink { param($u) $sync.AuthUrl = $u }
        Get-TRToolVersion
    }).AddArgument($modulePath).AddArgument($configPath)
try {
    $ver = $init.Invoke()
    if ($init.Streams.Error.Count) { throw $init.Streams.Error[0].Exception }
    $ui.TxtVersion.Text = $(if ($config -and $config.CompanyName -and [string]$config.CompanyName -ne 'Your Company') { [string]$config.CompanyName + ' | ' } else { '' }) + 'Version ' + ($ver | Select-Object -Last 1)
}
catch {
    Show-TRMessage ("The review engine could not be loaded: " + $_.Exception.Message) -Icon Error | Out-Null
    return
}
finally { $init.Dispose() }

$script:current = $null
$script:handle = $null
$script:signedIn = $false
$script:lastReport = $null
$script:lastPdf = $null
$script:lastSummaryPdf = $null
$script:lastFolder = $null
$script:lastAccount = $null
$script:lastTenant = $null
$script:signedInPlatform = $null

function Get-Platform {
    if ($ui.RbGoogle.IsChecked) { return 'Google' }
    'Microsoft'
}

function Set-PlatformUi {
    $g = (Get-Platform) -eq 'Google'
    $ui.TxtProduct.Text = $(if ($g) { 'Google Workspace Review' } else { 'Microsoft 365 Tenant Review' })
    $ui.LblTenant.Text = $(if ($g) { 'Primary domain of the Google Workspace (for example contoso.example)' } else { 'Tenant (onmicrosoft.com domain, verified domain or tenant ID)' })
    $ui.BtnConsent.Content = $(if ($g) { 'Trust the app' } else { 'Grant consent' })
    $ui.BtnConsent.ToolTip = $(if ($g) { 'First time only for each client. Shows how a super admin marks the review app as Trusted in the Google Admin console.' } else { 'First time only for each client tenant. Needs Cloud Application Administrator (GDAP) or the client''s Global Administrator.' })
    $ui.BtnRemoveApp.Content = $(if ($g) { 'Revoke the review app''s access' } else { 'Remove the review app from this tenant' })
    $ui.BtnRemoveApp.ToolTip = $(if ($g) { 'Tells Google to delete the sign-in tokens issued to the review app for this review.' } else { 'Deletes the review app and its permissions from the client tenant. You will need to Grant consent again before the next review.' })
    $ui.TxtRemoveApp.Text = $(if ($g) { 'Revoke the review app''s access when the review finishes' } else { 'Remove the review app from the client tenant when the review finishes (you sign in once more to approve it)' })
    $ui.PnlMsAreas.Visibility = $(if ($g) { 'Collapsed' } else { 'Visible' })
    $ui.PnlGoogleAreas.Visibility = $(if ($g) { 'Visible' } else { 'Collapsed' })
    $ui.PnlMsAdvanced.Visibility = $(if ($g) { 'Collapsed' } else { 'Visible' })
    $ui.PnlGoogleAdvanced.Visibility = $(if ($g) { 'Visible' } else { 'Collapsed' })
    if ($script:signedIn -and $script:signedInPlatform -ne (Get-Platform)) {
        $script:signedIn = $false
        $ui.TxtSignedIn.Text = 'Not signed in.'
        $ui.TxtSignedIn.Foreground = Get-Brush '#5F6B76'
    }
    Update-Buttons
}

function Show-TRGoogleTrustHelp {
    param([string]$ClientId)
    $nl = [Environment]::NewLine
    $text = 'Each client must trust the review app once before a super admin can sign in.' + $nl + $nl +
        '1. Sign in to admin.google.com as a super admin of the client.' + $nl +
        '2. Go to Security, Access and data control, API controls.' + $nl +
        '3. Select Manage third-party app access, then Configure new app.' + $nl +
        '4. Search for the client ID (copied to your clipboard) and select the review app.' + $nl +
        '5. Apply it to the whole organisation and set access to Trusted.' + $nl + $nl +
        'Wait a few minutes, then select Sign in. Open the Admin console page now?'
    if ($ClientId) { try { [System.Windows.Clipboard]::SetText($ClientId) } catch { } }
    $answer = Show-TRMessage $text -Title 'Trust the review app' -Icon Information -Buttons YesNo
    if ($answer -eq 'Yes') { Start-Process -FilePath $googleAdminUrl }
}

function Get-Brush {
    param([string]$Hex)
    (New-Object System.Windows.Media.BrushConverter).ConvertFromString($Hex)
}

function Add-LogLine {
    param([string]$Line)
    $ui.TxtLog.AppendText($Line + [Environment]::NewLine)
    if ($ui.TxtLog.Text.Length -gt 300000) { $ui.TxtLog.Text = $ui.TxtLog.Text.Substring($ui.TxtLog.Text.Length - 200000) }
    $ui.TxtLog.ScrollToEnd()
}

function Update-StatusLook {
    $pct = [int]$ui.PbMain.Value
    $ui.TxtPercent.Text = $(if ($sync.Busy -or $pct -gt 0) { '{0}%' -f $pct } else { '' })
    $fg = [string]$ui.TxtSignedIn.Foreground
    $tone = switch -Regex ($fg) { '2E7D32$' { '#E7F4E8' } 'B3261E$' { '#FCE8E6' } 'B26A00$' { '#FFF2DB' } default { '#EEF2F5' } }
    if ([string]$ui.BdSignedIn.Background -notmatch ($tone.Substring(1) + '$')) { $ui.BdSignedIn.Background = Get-Brush $tone }
}

function Set-AreaDefaults {
    param([switch]$None)
    $boxes = if ((Get-Platform) -eq 'Google') { $googleBoxes } else { $areaBoxes }
    foreach ($k in $boxes.Keys) { $boxes[$k].IsChecked = (-not $None) -and ($k -notin @('SharingAudit', 'DriveSharing')) }
}

function Update-Buttons {
    $busy = [bool]$sync.Busy
    $ui.BtnSignIn.IsEnabled = -not $busy
    $ui.BtnConsent.IsEnabled = -not $busy
    $ui.BtnRun.IsEnabled = (-not $busy) -and $script:signedIn
    $ui.BtnCancel.IsEnabled = $busy
    $ui.BtnRebuild.IsEnabled = -not $busy
    $ui.BtnBrowse.IsEnabled = -not $busy
    $ui.TxtTenant.IsEnabled = -not $busy
    $ui.BtnOpenReport.IsEnabled = [bool]$script:lastReport
    $ui.BtnOpenPdf.IsEnabled = [bool]$script:lastPdf
    $ui.BtnOpenSummary.IsEnabled = [bool]$script:lastSummaryPdf
    $ui.ChkServers.IsEnabled = -not $busy
    $ui.BtnAreasDefault.IsEnabled = -not $busy
    $ui.BtnAreasNone.IsEnabled = -not $busy
    $ui.TxtServerData.IsEnabled = -not $busy
    $ui.BtnServerBrowse.IsEnabled = -not $busy
    $ui.BtnOpenFolder.IsEnabled = [bool]$script:lastFolder
    $ui.BtnRemoveApp.IsEnabled = (-not $busy) -and ((Get-Platform) -eq 'Microsoft' -or ($script:signedIn -and $script:signedInPlatform -eq 'Google'))
    $ui.RbMicrosoft.IsEnabled = -not $busy
    $ui.RbGoogle.IsEnabled = -not $busy
    foreach ($b in $areaBoxes.Values) { $b.IsEnabled = -not $busy }
    foreach ($b in $googleBoxes.Values) { $b.IsEnabled = -not $busy }
}

function Start-Operation {
    param([string]$Name, [scriptblock]$Script, [object[]]$Arguments)
    if ($sync.Busy) { return }
    $sync.Busy = $true
    $sync.Cancel = $false
    $sync.Done = $false
    $sync.Error = $null
    $sync.Result = $null
    $sync.AuthUrl = ''
    $sync.Operation = $Name
    $sync.Percent = 0
    $ps = [powershell]::Create()
    $ps.Runspace = $runspace
    [void]$ps.AddScript($Script)
    foreach ($a in $Arguments) { [void]$ps.AddArgument($a) }
    $script:current = $ps
    $script:handle = $ps.BeginInvoke()
    Update-Buttons
}

function Save-GuiState {
    try {
        if (-not (Test-Path -LiteralPath $stateFolder)) { New-Item -ItemType Directory -Path $stateFolder -Force | Out-Null }
        $areas = @($areaBoxes.Keys | Where-Object { $areaBoxes[$_].IsChecked })
        $gAreas = @($googleBoxes.Keys | Where-Object { $googleBoxes[$_].IsChecked })
        [pscustomobject]@{ OutputRoot = $ui.TxtOutput.Text; Areas = $areas; KnownAreas = @($areaBoxes.Keys); GoogleAreas = $gAreas; GoogleKnownAreas = @($googleBoxes.Keys); Platform = (Get-Platform); RemoveApp = [bool]$ui.ChkRemoveApp.IsChecked; ServerDataPath = $ui.TxtServerData.Text; IncludeServers = [bool]$ui.ChkServers.IsChecked } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    }
    catch { }
}

function Get-ClientIdOrWarn {
    if ((Get-Platform) -eq 'Google') {
        $gid = $ui.TxtGoogleClientId.Text.Trim()
        if (-not $gid -or -not $googleSecret) {
            Show-TRMessage "No Google OAuth client is configured. Follow Google Workspace setup in the README to create the Google Cloud project for the review app, then add GoogleClientId and GoogleClientSecret to config.json." -Icon Warning | Out-Null
            return $null
        }
        return $gid
    }
    $id = $ui.TxtClientId.Text.Trim()
    if (-not $id) {
        Show-TRMessage "No app (client) ID is configured. Run New-TenantReviewApp.ps1 once to create the review app, or paste its client ID into config.json or Advanced." -Icon Warning | Out-Null
        return $null
    }
    $id
}

$ui.BtnSignIn.Add_Click({
        $tenant = $ui.TxtTenant.Text.Trim()
        if (-not $tenant) { Show-TRMessage $(if ((Get-Platform) -eq 'Google') { 'Enter the primary domain of the client''s Google Workspace.' } else { 'Enter the client tenant domain or ID.' }) -Icon Warning | Out-Null; return }
        $clientId = Get-ClientIdOrWarn
        if (-not $clientId) { return }
        $script:signedIn = $false
        $ui.TxtSignedIn.Text = 'Waiting for sign-in in the browser...'
        $ui.TxtSignedIn.Foreground = Get-Brush '#5F6B76'
        if ((Get-Platform) -eq 'Google') {
            Start-Operation -Name 'SignIn' -Arguments @($tenant, $clientId, $googleSecret) -Script {
                param($Domain, $ClientId, $Secret)
                try {
                    $ctx = Connect-TRGoogle -Domain $Domain -ClientId $ClientId -ClientSecret $Secret -OnAuthUrl { param($u) $sync.AuthUrl = $u }
                    $sync.Result = [pscustomobject]@{ Platform = 'Google'; Account = $ctx.Account; TenantName = $ctx.TenantName; TenantId = $ctx.CustomerId; Domain = $ctx.DefaultDomain; IsSuperAdmin = [bool]$ctx.IsSuperAdmin }
                }
                catch { $sync.Error = $_.Exception.Message; Write-TRLog $_.Exception.Message 'Error' }
                finally { $sync.Done = $true }
            }
            return
        }
        Start-Operation -Name 'SignIn' -Arguments @($tenant, $clientId) -Script {
            param($Tenant, $ClientId)
            try {
                $ctx = Connect-TRTenant -Tenant $Tenant -ClientId $ClientId -OnAuthUrl { param($u) $sync.AuthUrl = $u }
                $scopes = Test-TRGrantedScopes
                if ($scopes.Missing.Count) { Write-TRLog ('Consent is missing for: ' + ($scopes.Missing -join ', ') + '. Related checks will be Not assessed until Grant consent is run again.') 'Warn' }
                try { Get-TRAccessToken -Resource Exchange | Out-Null; Write-TRLog 'Exchange Online access token acquired.' 'Success' }
                catch { Write-TRLog ('Exchange Online token could not be acquired: ' + $_.Exception.Message) 'Warn' }
                $sync.Result = [pscustomobject]@{ Platform = 'Microsoft'; Account = $ctx.Account; TenantName = $ctx.TenantName; TenantId = $ctx.TenantId; Domain = $ctx.DefaultDomain }
            }
            catch { $sync.Error = $_.Exception.Message; Write-TRLog $_.Exception.Message 'Error' }
            finally { $sync.Done = $true }
        }
    })

$ui.BtnConsent.Add_Click({
        if ((Get-Platform) -eq 'Google') {
            Show-TRGoogleTrustHelp -ClientId $ui.TxtGoogleClientId.Text.Trim()
            return
        }
        $tenant = $ui.TxtTenant.Text.Trim()
        if (-not $tenant) { Show-TRMessage 'Enter the client tenant domain or ID.' -Icon Warning | Out-Null; return }
        $clientId = Get-ClientIdOrWarn
        if (-not $clientId) { return }
        Start-Operation -Name 'Consent' -Arguments @($tenant, $clientId) -Script {
            param($Tenant, $ClientId)
            try { Request-TRAdminConsent -Tenant $Tenant -ClientId $ClientId -OnAuthUrl { param($u) $sync.AuthUrl = $u } | Out-Null; $sync.Result = $true }
            catch { $sync.Error = $_.Exception.Message; Write-TRLog $_.Exception.Message 'Error' }
            finally { $sync.Done = $true }
        }
    })

function Start-RemoveApp {
    param([string]$Tenant, [string]$ClientId)
    if ((Get-Platform) -eq 'Google') {
        $ui.TxtActivity.Text = 'Revoking the review app''s access.'
        Start-Operation -Name 'RemoveApp' -Arguments @($Tenant) -Script {
            param($Tenant)
            try {
                $removed = Remove-TRGoogleAccess
                $sync.Result = [pscustomobject]@{ Removed = [bool]$removed; Tenant = $Tenant; Platform = 'Google' }
            }
            catch { $sync.Error = $_.Exception.Message; Write-TRLog $_.Exception.Message 'Error' }
            finally { $sync.Done = $true }
        }
        return
    }
    $ui.TxtActivity.Text = 'Removing the review app: sign in in the browser and approve the request.'
    Start-Operation -Name 'RemoveApp' -Arguments @($Tenant, $ClientId, $script:lastAccount) -Script {
        param($Tenant, $ClientId, $Hint)
        try {
            $removed = Remove-TRTenantApp -Tenant $Tenant -ClientId $ClientId -LoginHint $Hint -OnAuthUrl { param($u) $sync.AuthUrl = $u }
            $sync.Result = [pscustomobject]@{ Removed = [bool]$removed; Tenant = $Tenant; Platform = 'Microsoft' }
        }
        catch { $sync.Error = $_.Exception.Message; Write-TRLog $_.Exception.Message 'Error' }
        finally { $sync.Done = $true }
    }
}

$ui.BtnRemoveApp.Add_Click({
        if ((Get-Platform) -eq 'Google') {
            $answer = Show-TRMessage ("This revokes the sign-in tokens Google issued to the review app for {0}. You will need to sign in again before the next review.{1}{1}Continue?" -f $script:lastAccount, [Environment]::NewLine) -Icon Question -Buttons YesNo
            if ($answer -ne 'Yes') { return }
            Start-RemoveApp -Tenant $ui.TxtTenant.Text.Trim() -ClientId $ui.TxtGoogleClientId.Text.Trim()
            return
        }
        $tenant = $ui.TxtTenant.Text.Trim()
        if (-not $tenant) { Show-TRMessage 'Enter the client tenant domain or ID.' -Icon Warning | Out-Null; return }
        $clientId = Get-ClientIdOrWarn
        if (-not $clientId) { return }
        $answer = Show-TRMessage ("This removes the review app and all of its permissions from {0}.{1}{1}You will need to use Grant consent again before the next review of this client. Continue?" -f $tenant, [Environment]::NewLine) -Icon Question -Buttons YesNo
        if ($answer -ne 'Yes') { return }
        Start-RemoveApp -Tenant $tenant -ClientId $clientId
    })

$ui.BtnCopyLink.Add_Click({
        if ($sync.AuthUrl) { [System.Windows.Clipboard]::SetText([string]$sync.AuthUrl); $ui.TxtActivity.Text = 'Sign-in link copied. Paste it into the browser profile you want to use.' }
    })

$ui.BtnBrowse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Choose where review reports are saved'
        if (Test-Path -LiteralPath $ui.TxtOutput.Text) { $dlg.SelectedPath = $ui.TxtOutput.Text }
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $ui.TxtOutput.Text = $dlg.SelectedPath }
    })

function Get-ServerDataPath {
    if (-not $ui.ChkServers.IsChecked) { return '' }
    $p = $ui.TxtServerData.Text.Trim()
    if (-not $p -or -not (Test-Path -LiteralPath $p)) {
        Show-TRMessage 'Choose the folder that holds the server data files (.server-review.json), or untick Include server data.' -Icon Warning | Out-Null
        return $null
    }
    $p
}

$ui.BtnAreasDefault.Add_Click({ Set-AreaDefaults })
$ui.BtnAreasNone.Add_Click({ Set-AreaDefaults -None })

$ui.BtnServerBrowse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = 'Choose the folder that holds the .server-review.json files'
        if ($ui.TxtServerData.Text -and (Test-Path -LiteralPath $ui.TxtServerData.Text)) { $dlg.SelectedPath = $ui.TxtServerData.Text }
        if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $ui.TxtServerData.Text = $dlg.SelectedPath; $ui.ChkServers.IsChecked = $true }
    })

$ui.BtnRun.Add_Click({
        $out = $ui.TxtOutput.Text.Trim()
        if (-not $out) { Show-TRMessage 'Choose a reports folder.' -Icon Warning | Out-Null; return }
        $srvPath = Get-ServerDataPath
        if ($null -eq $srvPath) { return }
        $boxes = if ((Get-Platform) -eq 'Google') { $googleBoxes } else { $areaBoxes }
        $areas = @('Identity', 'Licensing') + @($boxes.Keys | Where-Object { $boxes[$_].IsChecked })
        $client = $ui.TxtClient.Text.Trim()
        Save-GuiState
        Start-Operation -Name 'Review' -Arguments @($areas, $client, $out, $srvPath) -Script {
            param($Areas, $Client, $Out, $ServerPath)
            try {
                $r = Invoke-TenantReview -Areas $Areas -ClientName $Client -OutputRoot $Out -ServerDataPath $ServerPath
                $sync.Result = [pscustomobject]@{ Html = $r.Html; Pdf = $r.Pdf; SummaryPdf = $r.SummaryPdf; Folder = $r.OutputFolder; Score = $r.Score; Fail = $r.Fail; Warning = $r.Warning; Pass = $r.Pass; NotAssessed = $r.NotAssessed; NotUsed = $r.NotUsed; PartlyUsed = $r.PartlyUsed; HasOpps = (@($r.Opportunities).Count -gt 0); AzureScore = $r.AzureScore; ServerScore = $r.ServerScore; Bench = ((@($r.BenchmarkSummary) | Where-Object { $_ } | ForEach-Object { '{0} {1}' -f $_.Short, $(if ($null -ne $_.Score) { [string]$_.Score + '%' } else { 'not scored' }) }) -join ', ') }
            }
            catch { $sync.Error = $_.Exception.Message; Write-TRLog $_.Exception.Message 'Error' }
            finally { $sync.Done = $true }
        }
    })

$ui.BtnRebuild.Add_Click({
        $dlg = New-Object Microsoft.Win32.OpenFileDialog
        $dlg.Filter = 'Review data (RawData.json)|RawData.json|JSON files (*.json)|*.json'
        $dlg.Title = 'Choose a RawData.json file from a previous review'
        if (Test-Path -LiteralPath $ui.TxtOutput.Text) { $dlg.InitialDirectory = $ui.TxtOutput.Text }
        if (-not $dlg.ShowDialog($window)) { return }
        $srvPath = Get-ServerDataPath
        if ($null -eq $srvPath) { return }
        Save-GuiState
        Start-Operation -Name 'Rebuild' -Arguments @($dlg.FileName, $srvPath) -Script {
            param($RawPath, $ServerPath)
            try {
                $r = Invoke-TenantAnalysis -RawPath $RawPath -ServerDataPath $ServerPath
                $sync.Result = [pscustomobject]@{ Html = $r.Html; Pdf = $r.Pdf; SummaryPdf = $r.SummaryPdf; Folder = $r.OutputFolder; Score = $r.Score; Fail = $r.Fail; Warning = $r.Warning; Pass = $r.Pass; NotAssessed = $r.NotAssessed; NotUsed = $r.NotUsed; PartlyUsed = $r.PartlyUsed; HasOpps = (@($r.Opportunities).Count -gt 0); AzureScore = $r.AzureScore; ServerScore = $r.ServerScore; Bench = ((@($r.BenchmarkSummary) | Where-Object { $_ } | ForEach-Object { '{0} {1}' -f $_.Short, $(if ($null -ne $_.Score) { [string]$_.Score + '%' } else { 'not scored' }) }) -join ', ') }
            }
            catch { $sync.Error = $_.Exception.Message; Write-TRLog $_.Exception.Message 'Error' }
            finally { $sync.Done = $true }
        }
    })

$ui.BtnCancel.Add_Click({
        if ($sync.Busy) {
            $sync.Cancel = $true
            $ui.TxtActivity.Text = 'Cancelling after the current step...'
        }
    })

$ui.BtnOpenReport.Add_Click({ if ($script:lastReport -and (Test-Path -LiteralPath $script:lastReport)) { Start-Process -FilePath $script:lastReport } })
$ui.BtnShortcut.Add_Click({
        try {
            $desktop = [Environment]::GetFolderPath('Desktop')
            $shell = New-Object -ComObject WScript.Shell
            $lnk = $shell.CreateShortcut((Join-Path $desktop 'Tenant Review.lnk'))
            $lnk.TargetPath = Join-Path $root 'Start-TenantReview.cmd'
            $lnk.WorkingDirectory = $root
            $lnk.WindowStyle = 7
            $lnk.Description = 'Tenant Review'
            if (Test-Path -LiteralPath $iconPath -PathType Leaf) { $lnk.IconLocation = $iconPath + ',0' }
            $lnk.Save()
            Show-TRMessage 'A "Tenant Review" shortcut has been added to your desktop.' | Out-Null
        }
        catch { Show-TRMessage ('The shortcut could not be created: ' + $_.Exception.Message) -Icon Warning | Out-Null }
    })
$ui.BtnOpenPdf.Add_Click({ if ($script:lastPdf -and (Test-Path -LiteralPath $script:lastPdf)) { Start-Process -FilePath $script:lastPdf } })
$ui.BtnOpenSummary.Add_Click({ if ($script:lastSummaryPdf -and (Test-Path -LiteralPath $script:lastSummaryPdf)) { Start-Process -FilePath $script:lastSummaryPdf } })
$ui.BtnOpenFolder.Add_Click({ if ($script:lastFolder -and (Test-Path -LiteralPath $script:lastFolder)) { Start-Process -FilePath 'explorer.exe' -ArgumentList ('"{0}"' -f $script:lastFolder) } })

$timer = New-Object System.Windows.Threading.DispatcherTimer
$timer.Interval = [TimeSpan]::FromMilliseconds(200)
$timer.Add_Tick({
        $line = $null
        $n = 0
        while ($n -lt 200 -and $sync.Log.TryDequeue([ref]$line)) { Add-LogLine $line; $n++ }
        Update-StatusLook
        if ($sync.Busy) {
            $ui.PbMain.Value = [double]$sync.Percent
            if ($sync.Activity) { $ui.TxtActivity.Text = [string]$sync.Activity }
            $ui.BtnCopyLink.Visibility = $(if ($sync.AuthUrl -and $sync.Operation -in @('SignIn', 'Consent', 'RemoveApp', 'Review')) { 'Visible' } else { 'Collapsed' })
        }
        if ($sync.Busy -and $sync.Done) {
            try { $script:current.EndInvoke($script:handle) | Out-Null } catch { }
            foreach ($e in $script:current.Streams.Error) { Add-LogLine ('ERROR ' + $e.ToString()) }
            $script:current.Dispose()
            $script:current = $null
            $op = $sync.Operation
            $res = $sync.Result
            $err = $sync.Error
            $sync.Busy = $false
            $ui.BtnCopyLink.Visibility = 'Collapsed'
            switch ($op) {
                'SignIn' {
                    if ($res) {
                        $script:signedIn = $true
                        $script:signedInPlatform = [string]$res.Platform
                        $script:lastAccount = [string]$res.Account
                        $script:lastTenant = $ui.TxtTenant.Text.Trim()
                        if ($res.Platform -eq 'Google') {
                            $ui.TxtSignedIn.Text = ('Signed in as {0}{1}Organisation: {2} ({3}){1}Customer ID {4}' -f $res.Account, [Environment]::NewLine, $res.TenantName, $res.Domain, $res.TenantId)
                            if (-not $res.IsSuperAdmin) { $ui.TxtSignedIn.Text += ([Environment]::NewLine + 'This account is not a super admin, so some areas may be Not assessed.') }
                        }
                        else { $ui.TxtSignedIn.Text = ('Signed in as {0}{1}Tenant: {2} ({3}){1}{4}' -f $res.Account, [Environment]::NewLine, $res.TenantName, $res.Domain, $res.TenantId) }
                        $ui.TxtSignedIn.Foreground = Get-Brush $(if ($res.Platform -eq 'Google' -and -not $res.IsSuperAdmin) { '#B26A00' } else { '#2E7D32' })
                        if (-not $ui.TxtClient.Text.Trim()) { $ui.TxtClient.Text = [string]$res.TenantName }
                        $ui.TxtActivity.Text = 'Signed in. Choose the review areas and select Run review.'
                    }
                    else {
                        $ui.TxtSignedIn.Text = 'Sign-in failed: ' + $err
                        $ui.TxtSignedIn.Foreground = Get-Brush '#B3261E'
                        $ui.TxtActivity.Text = 'Sign-in failed.'
                    }
                }
                'Consent' {
                    if ($res) { $ui.TxtActivity.Text = 'Consent granted. Wait a minute, then sign in.' }
                    else { $ui.TxtActivity.Text = 'Consent did not complete: ' + $err }
                }
                'RemoveApp' {
                    $script:signedIn = $false
                    if ($res -and $res.Platform -eq 'Google') {
                        $ui.TxtSignedIn.Text = ('The review app''s access to {0} has been revoked. If the app was marked as Trusted for this review only, remove it in the Admin console under API controls.' -f $res.Tenant)
                        $ui.TxtSignedIn.Foreground = Get-Brush '#5F6B76'
                        $ui.TxtActivity.Text = 'Access revoked.'
                    }
                    elseif ($res -and $res.Removed) {
                        $ui.TxtSignedIn.Text = ('The review app has been removed from {0}. Use Grant consent before the next review.' -f $res.Tenant)
                        $ui.TxtSignedIn.Foreground = Get-Brush '#5F6B76'
                        $ui.TxtActivity.Text = 'The review app has been removed from the client tenant.'
                    }
                    elseif ($res) {
                        $ui.TxtSignedIn.Text = 'The review app was not present in this tenant. Nothing was removed.'
                        $ui.TxtSignedIn.Foreground = Get-Brush '#5F6B76'
                        $ui.TxtActivity.Text = 'Nothing to remove.'
                    }
                    elseif ((Get-Platform) -eq 'Google') {
                        $ui.TxtActivity.Text = 'Access was not revoked: ' + $err
                        Show-TRMessage ('The review app''s access was not revoked.{0}{0}{1}{0}{0}A super admin can remove it in the Admin console: Security, Access and data control, API controls.' -f [Environment]::NewLine, $err) -Icon Warning | Out-Null
                    }
                    else {
                        $ui.TxtActivity.Text = 'The app was not removed: ' + $err
                        Show-TRMessage ('The review app was not removed from the tenant.{0}{0}{1}{0}{0}You can try again with Remove the review app from this tenant, or delete the enterprise application in the Entra admin centre.' -f [Environment]::NewLine, $err) -Icon Warning | Out-Null
                    }
                }
                default {
                    if ($res) {
                        $script:lastReport = $res.Html
                        $script:lastPdf = $res.Pdf
                        $script:lastSummaryPdf = $res.SummaryPdf
                        $script:lastFolder = $res.Folder
                        $ui.PbMain.Value = 100
                        $done = 'Complete. Score {0}%: {1} fail, {2} warning, {3} pass, {4} not assessed.' -f $res.Score, $res.Fail, $res.Warning, $res.Pass, $res.NotAssessed
                        if ($res.HasOpps) { $done += (' Licensed features not used: {0}; partly used: {1}.' -f $res.NotUsed, $res.PartlyUsed) }
                        if ($res.Bench) { $done += (' Benchmarks: {0}.' -f $res.Bench) }
                        if ($null -ne $res.AzureScore) { $done += (' Azure: {0}%.' -f $res.AzureScore) }
                        if ($null -ne $res.ServerScore) { $done += (' Servers: {0}%.' -f $res.ServerScore) }
                        $ui.TxtActivity.Text = $done
                        if ($ui.ChkOpen.IsChecked -and (Test-Path -LiteralPath $res.Html)) { Start-Process -FilePath $res.Html }
                        if ($op -eq 'Review' -and $ui.ChkRemoveApp.IsChecked) {
                            $tenantNow = $ui.TxtTenant.Text.Trim()
                            $clientNow = if ((Get-Platform) -eq 'Google') { $ui.TxtGoogleClientId.Text.Trim() } else { $ui.TxtClientId.Text.Trim() }
                            if ($tenantNow -and $clientNow) {
                                Update-Buttons
                                Start-RemoveApp -Tenant $tenantNow -ClientId $clientNow
                                return
                            }
                        }
                    }
                    else {
                        $ui.TxtActivity.Text = 'Stopped: ' + $err
                    }
                }
            }
            Update-Buttons
        }
    })

$window.Add_Closing({
        param($s, $e)
        if ($sync.Busy) {
            $answer = Show-TRMessage 'A task is still running. Stop it and close?' -Icon Question -Buttons YesNo
            if ($answer -ne 'Yes') { $e.Cancel = $true; return }
            $sync.Cancel = $true
            try { $script:current.Stop() } catch { }
        }
        Save-GuiState
        $timer.Stop()
        try { $runspace.Close(); $runspace.Dispose() } catch { }
    })

$ui.RbMicrosoft.Add_Checked({ Set-PlatformUi })
$ui.RbGoogle.Add_Checked({ Set-PlatformUi })
if ($guiState -and $guiState.PSObject.Properties['Platform'] -and [string]$guiState.Platform -eq 'Google') { $ui.RbGoogle.IsChecked = $true }
Set-PlatformUi
$timer.Start()
Add-LogLine ('Ready. Choose Microsoft 365 or Google Workspace, enter the client, then Sign in. Tokens are held in memory only and are discarded when this window closes.')
[void]$window.ShowDialog()
