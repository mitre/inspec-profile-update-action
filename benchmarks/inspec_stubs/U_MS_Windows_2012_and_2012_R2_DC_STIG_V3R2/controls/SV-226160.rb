control 'SV-226160' do
  title 'Group Policies must be refreshed in the background if the user is logged on.'
  desc 'If this setting is enabled, then Group Policy settings are not refreshed while a user is currently logged on.  This could lead to instances when a user does not have the latest changes to a policy applied and is therefore operating in an insecure context.'
  desc 'check', 'Review the registry.
If the following registry value does not exist, this is not a finding (this is the expected result from configuring the policy as outlined in the Fix section.):
If the following registry value exists but is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\system\\

Value Name: DisableBkGndGroupPolicy

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Group Policy -> "Turn off background refresh of Group Policy" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27862r475803_chk'
  tag severity: 'medium'
  tag gid: 'V-226160'
  tag rid: 'SV-226160r569184_rule'
  tag stig_id: 'WN12-CC-000029'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27850r475804_fix'
  tag 'documentable'
  tag legacy: ['SV-52906', 'V-3469']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
