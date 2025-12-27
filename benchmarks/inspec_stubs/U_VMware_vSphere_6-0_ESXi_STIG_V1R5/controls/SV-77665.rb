control 'SV-77665' do
  title 'The system must verify the exception users list for lockdown mode.'
  desc 'In vSphere 6.0 and later, you can add users to the Exception Users list from the vSphere Web Client. These users do not lose their permissions when the host enters lockdown mode. Usually you may want to add service accounts such as a backup agent to the Exception Users list. Verify that the list of users who are exempted from losing permissions is legitimate and as needed per your environment. Users who do not require special permissions should not be exempted from lockdown mode.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Settings >> Security Profile.  Under lockdown mode review the exception users list.

or

From a PowerCLI command prompt while connected to the ESXi host run the following script:

$vmhost = Get-VMHost | Get-View
$lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
$lockdown.QueryLockdownExceptions()

If the exception users list contains accounts that do not require special permissions, this is a finding.

Note: This list is not intended for system administrator accounts but for special circumstances such as a service account.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Manage >> Settings >> Security Profile.  Under lockdown mode click Edit and remove unnecessary users to the exceptions list.'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63909r1_chk'
  tag severity: 'low'
  tag gid: 'V-63175'
  tag rid: 'SV-77665r1_rule'
  tag stig_id: 'ESXI-06-000003'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69093r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
