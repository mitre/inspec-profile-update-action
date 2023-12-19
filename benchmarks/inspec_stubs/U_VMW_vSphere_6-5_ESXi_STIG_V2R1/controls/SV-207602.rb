control 'SV-207602' do
  title 'The ESXi host must limit the number of concurrent sessions to ten for all accounts and/or account types by enabling lockdown mode.'
  desc 'Enabling lockdown mode disables direct access to an ESXi host requiring the host be managed remotely from vCenter Server. This is done to ensure the roles and access controls implemented in vCenter are always enforced and users cannot bypass them by logging into a host directly. By forcing all interaction to occur through vCenter Server, the risk of someone inadvertently attaining elevated privileges or performing tasks that are not properly audited is greatly reduced.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Security Profile.  Scroll down to "Lockdown Mode" and verify it is set to Enabled (Normal or Strict).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}

If Lockdown Mode is disabled, this is a finding. 

For environments that do not use vCenter server to manage ESXi, this is not applicable.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Security Profile. Click edit on "Lockdown Mode" and set to Enabled (Normal or Strict).

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

$level = "lockdownNormal" OR "lockdownStrict"
$vmhost = Get-VMHost -Name <hostname> | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.ChangeLockdownMode($level)

Note: In strict lockdown mode the DCUI service is stopped. If the connection to vCenter Server is lost and the vSphere Web Client is no longer available, the ESXi host becomes inaccessible.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7857r364205_chk'
  tag severity: 'medium'
  tag gid: 'V-207602'
  tag rid: 'SV-207602r378532_rule'
  tag stig_id: 'ESXI-65-000001'
  tag gtitle: 'SRG-OS-000027-VMM-000080'
  tag fix_id: 'F-7857r364206_fix'
  tag 'documentable'
  tag legacy: ['SV-104035', 'V-93949']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
