control 'SV-77637' do
  title 'The VMM must limit the number of concurrent sessions to ten for all accounts and/or account types by enabling lockdown mode.'
  desc 'Enabling lockdown mode disables direct access to an ESXi host requiring the host be managed remotely from vCenter Server. This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging into a host directly. By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Settings >> System >> Security Profile.  Scroll down to "Lockdown Mode" and verify it is set to Enabled (Normal or Strict).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}

If Lockdown Mode is disabled, this is a finding.  

For environments that do not use vCenter server to manage ESXi, this is not applicable.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Settings >> System >> Security Profile.  Click edit on "Lockdown Mode" and set to Enabled (Normal or Strict).

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

$level = "lockdownNormal" OR "lockdownStrict"
$vmhost = Get-VMHost -Name <hostname> | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.ChangeLockdownMode($level)

Note: In strict lockdown mode, which is new in vSphere 6.0, the DCUI service is stopped. If the connection to vCenter Server is lost and the vSphere Web Client is no longer available, the ESXi host becomes inaccessible.'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63899r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63147'
  tag rid: 'SV-77637r1_rule'
  tag stig_id: 'ESXI-06-000001'
  tag gtitle: 'SRG-OS-000027-VMM-000080'
  tag fix_id: 'F-69065r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
