control 'SV-216839' do
  title 'The vCenter Server for Windows must not override port group settings at the port level on distributed switches.'
  desc 'Port-level configuration overrides are disabled by default. Once enabled, this allows for different security settings to be set from what is established at the Port-Group level. There are cases where particular VMs require unique configurations, but this should be monitored so it is only used when authorized. If overrides are not monitored, anyone who gains access to a VM with a less secure VDS configuration could surreptitiously exploit that broader access.'
  desc 'check', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties. 

View the Properties pane and verify all Override port policies are set to disabled.

or

From a PowerCLI command prompt while connected to the vCenter server run the following command:
Get-VDPortgroup | Get-View | 
Select Name,
@{N="VlanOverrideAllowed";E={$_.Config.Policy.VlanOverrideAllowed}},
@{N="UplinkTeamingOverrideAllowed";E={$_.Config.Policy.UplinkTeamingOverrideAllowed}},
@{N="SecurityPolicyOverrideAllowed";E={$_.Config.Policy.SecurityPolicyOverrideAllowed}},
@{N="IpfixOverrideAllowed";E={$_.Config.Policy.IpfixOverrideAllowed}},
@{N="BlockOverrideAllowed";E={$_.Config.Policy.BlockOverrideAllowed}},
@{N="ShapingOverrideAllowed";E={$_.Config.Policy.ShapingOverrideAllowed}},
@{N="VendorConfigOverrideAllowed";E={$_.Config.Policy.VendorConfigOverrideAllowed}},
@{N="TrafficFilterOverrideAllowed";E={$_.Config.Policy.TrafficFilterOverrideAllowed}},
@{N="PortConfigResetAtDisconnect";E={$_.Config.Policy.PortConfigResetAtDisconnect}} | Sort Name

Note: This was broken up into multiple lines for readability. Either paste as is into a PowerShell script or combine into one line and run.

This does not apply to the reset port configuration on disconnect policy.

If any port level overrides are enabled and not documented, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Networking >> Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties. Click "Edit" and change all Override port policies to disabled.

From a PowerCLI command prompt while connected to the vCenter server run the following commands:
$pgs = Get-VDPortgroup | Get-View
ForEach($pg in $pgs){
$spec = New-Object VMware.Vim.DVPortgroupConfigSpec
$spec.configversion = $pg.Config.ConfigVersion
$spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
$spec.Policy.VlanOverrideAllowed = $False
$spec.Policy.UplinkTeamingOverrideAllowed = $False
$spec.Policy.SecurityPolicyOverrideAllowed = $False
$spec.Policy.IpfixOverrideAllowed = $False
$spec.Policy.BlockOverrideAllowed = $False
$spec.Policy.ShapingOverrideAllowed = $False
$spec.Policy.VendorConfigOverrideAllowed = $False
$spec.Policy.TrafficFilterOverrideAllowed = $False
$spec.Policy.PortConfigResetAtDisconnect = $True
$pg.ReconfigureDVPortgroup_Task($spec)
}'
  impact 0.3
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18070r366231_chk'
  tag severity: 'low'
  tag gid: 'V-216839'
  tag rid: 'SV-216839r879887_rule'
  tag stig_id: 'VCWN-65-000017'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-18068r366232_fix'
  tag 'documentable'
  tag legacy: ['SV-104575', 'V-94745']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
