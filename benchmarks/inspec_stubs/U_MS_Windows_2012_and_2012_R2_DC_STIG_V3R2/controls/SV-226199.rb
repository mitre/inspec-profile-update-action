control 'SV-226199' do
  title 'Passwords must not be saved in the Remote Desktop Client.'
  desc 'Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop session to another system.  The system must be configured to prevent users from saving passwords in the Remote Desktop Client.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: DisablePasswordSaving

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Connection Client -> "Do not allow passwords to be saved" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27901r475920_chk'
  tag severity: 'medium'
  tag gid: 'V-226199'
  tag rid: 'SV-226199r569184_rule'
  tag stig_id: 'WN12-CC-000096'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-27889r475921_fix'
  tag 'documentable'
  tag legacy: ['SV-52958', 'V-14247']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
