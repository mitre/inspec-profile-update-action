control 'SV-226147' do
  title 'The Windows Connect Now wizards must be disabled.'
  desc 'Windows Connect Now provides wizards for tasks such as "Set up a wireless router or access point" and must not be available to users.  Functions such as these may allow unauthorized connections to a system and the potential for sensitive information to be compromised.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WCN\\UI\\

Value Name: DisableWcnUi

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now -> "Prohibit access of the Windows Connect Now wizards" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27849r475764_chk'
  tag severity: 'medium'
  tag gid: 'V-226147'
  tag rid: 'SV-226147r569184_rule'
  tag stig_id: 'WN12-CC-000013'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27837r475765_fix'
  tag 'documentable'
  tag legacy: ['SV-53089', 'V-15699']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
