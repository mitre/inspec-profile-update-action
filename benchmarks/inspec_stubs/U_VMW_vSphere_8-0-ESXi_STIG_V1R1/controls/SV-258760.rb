control 'SV-258760' do
  title 'The ESXi host lockdown mode exception users list must be verified.'
  desc 'While a host is in lockdown mode (strict or normal), only users on the "Exception Users" list are allowed access. These users do not lose their permissions when the host enters lockdown mode. 

The organization may want to add service accounts such as a backup agent to the Exception Users list. Verify the list of users exempted from losing permissions is legitimate and as needed per the environment. Adding unnecessary users to the exception list defeats the purpose of lockdown mode.'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Under "Lockdown Mode", review the Exception Users list.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following script:

$vmhost = Get-VMHost | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.QueryLockdownExceptions()

If the Exception Users list contains accounts that do not require special permissions, this is a finding.

Note: The Exception Users list is empty by default and should remain that way except under site-specific circumstances.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Under "Lockdown Mode", click "Edit" and remove unnecessary users from the Exception Users list.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62500r933339_chk'
  tag severity: 'medium'
  tag gid: 'V-258760'
  tag rid: 'SV-258760r933341_rule'
  tag stig_id: 'ESXI-80-000201'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62409r933340_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
