control 'SV-48203' do
  title 'Passwords must not be saved in the Remote Desktop Client.'
  desc 'Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system.  The system must be configured to prevent users from saving passwords in the Remote Desktop Client.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: DisablePasswordSaving

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client -> "Do not allow passwords to be saved" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44882r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14247'
  tag rid: 'SV-48203r1_rule'
  tag stig_id: 'WN08-CC-000096'
  tag gtitle: 'TS/RDS - Prevent Password Saving'
  tag fix_id: 'F-41339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
