control 'SV-258966' do
  title 'The vCenter Server must not override port group settings at the port level on distributed switches.'
  desc 'Port-level configuration overrides are disabled by default. Once enabled, this allows for different security settings to be set from what is established at the Port Group level. If overrides are not monitored, anyone who gains access to a VM with a less secure VDS configuration could exploit that broader access.

If there are cases where particular VMs require unique configurations then a different port group with the required configuration should be created instead of overriding port group settings.'
  desc 'check', 'If distributed switches are not used, this is not applicable.

From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties.

Review the "Override port policies".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

(Get-VDPortgroup).ExtensionData.Config.Policy

If there are any distributed port groups that allow overridden port policies, this is a finding.

Note: This does not apply to the "Block Ports" or "Configure reset at disconnect" policies.'
  desc 'fix', 'From the vSphere Client, go to "Networking".

Select a distributed switch >> Select a distributed port group >> Configure >> Settings >> Properties.

Click "Edit".

Select advanced and update all port policies besides "Block Ports" to "disabled" and click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

$pgs = Get-VDPortgroup | Get-View
ForEach($pg in $pgs){
$spec = New-Object VMware.Vim.DVPortgroupConfigSpec
$spec.configversion = $pg.Config.ConfigVersion
$spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
$spec.Policy.VlanOverrideAllowed = $False
$spec.Policy.UplinkTeamingOverrideAllowed = $False
$spec.Policy.SecurityPolicyOverrideAllowed = $False
$spec.Policy.IpfixOverrideAllowed = $False
$spec.Policy.BlockOverrideAllowed = $True
$spec.Policy.ShapingOverrideAllowed = $False
$spec.Policy.VendorConfigOverrideAllowed = $False
$spec.Policy.TrafficFilterOverrideAllowed = $False
$pg.ReconfigureDVPortgroup_Task($spec)
}'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 vCenter'
  tag check_id: 'C-62706r934554_chk'
  tag severity: 'medium'
  tag gid: 'V-258966'
  tag rid: 'SV-258966r934556_rule'
  tag stig_id: 'VCSA-80-000301'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62615r934555_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
