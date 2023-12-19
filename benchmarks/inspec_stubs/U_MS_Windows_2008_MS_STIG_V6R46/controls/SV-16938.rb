control 'SV-16938' do
  title 'Terminal Services is not configured to limit users to one remote session (Terminal Server Role)'
  desc 'This setting limits users to one remote session.  It is possible, if this setting is disabled, for users to establish multiple sessions.'
  desc 'check', '2008 - If the following registry value doesn’t exist or its value is not set to 1, then this is a finding:
Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name:	fSingleSessionPerUser
Type: REG_DWORD
Value:  1

Documentable Explanation: If the system has the role as a Terminal Server, or the site is using terminal services for remote administration this requirement needs to be documented with the IAO.'
  desc 'fix', '2008 - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services -> Terminal Server -> Connections “Restrict Terminal Server users to a Single Remote Session” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-16761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3449'
  tag rid: 'SV-16938r1_rule'
  tag gtitle: 'TS/RDS -  Session Limit'
  tag fix_id: 'F-16009r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
