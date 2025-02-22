control 'SV-32498' do
  title 'Remote Desktop Services will limit users to one remote session.'
  desc 'This setting limits users to one remote session.  It is possible, if this setting is disabled, for users to establish multiple sessions.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding: 

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\ 

Value Name: fSingleSessionPerUser 

Type: REG_DWORD 
Value: 1 

Documentable Explanation: If the system has the role as a Terminal/Remote Desktop Server or the site is using remote desktop services for remote administration, this requirement needs to be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Remote Desktop Services -> Remote Desktop Session Host -> Connections “Restrict Remote Desktop Services users to a Single Remote Desktop Services Session” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32895r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3449'
  tag rid: 'SV-32498r1_rule'
  tag gtitle: 'TS/RDS -  Session Limit'
  tag fix_id: 'F-28894r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
