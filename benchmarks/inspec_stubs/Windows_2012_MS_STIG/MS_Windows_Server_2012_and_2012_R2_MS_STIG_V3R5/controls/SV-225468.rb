control 'SV-225468' do
  title 'Users must be warned in advance of their passwords expiring.'
  desc 'Creating strong passwords that can be remembered by users requires some thought.  By giving the user advance warning, the user has time to construct a sufficiently strong password.  This setting configures the system to display a warning to users telling them how many days are left before their password expires.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: PasswordExpiryWarning

Value Type: REG_DWORD
Value: 14 (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Interactive Logon: Prompt user to change password before expiration" to "14" days or more.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27167r471746_chk'
  tag severity: 'low'
  tag gid: 'V-225468'
  tag rid: 'SV-225468r569185_rule'
  tag stig_id: 'WN12-SO-000025'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27155r471747_fix'
  tag 'documentable'
  tag legacy: ['SV-52876', 'V-1172']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
