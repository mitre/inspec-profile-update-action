control 'SV-239260' do
  title 'The ESXi host must verify the exception users list for Lockdown Mode.'
  desc 'In vSphere, users can be added to the Exception Users list from the vSphere Web Client. These users do not lose their permissions when the host enters Lockdown Mode. 

Before adding service accounts such as a backup agent to the Exception Users list, verify that the list of users who are exempted from losing permissions is legitimate and as needed per the environment. Users who do not require special permissions should not be exempted from Lockdown Mode.'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is Not Applicable.

From the vSphere Client, select the ESXi host and go to Configure >> System >> Security Profile. 

Under Lockdown Mode, review the Exception Users list.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following script:

$vmhost = Get-VMHost | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.QueryLockdownExceptions()

If the Exception Users list contains accounts that do not require special permissions, this is a finding.

Note: This list is not intended for system administrator accounts but for special circumstances such as a service account.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Security Profile. 

Under "Lockdown Mode", click "Edit" and remove unnecessary users from the exceptions list.'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42493r674707_chk'
  tag severity: 'low'
  tag gid: 'V-239260'
  tag rid: 'SV-239260r674709_rule'
  tag stig_id: 'ESXI-67-000003'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42452r674708_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
