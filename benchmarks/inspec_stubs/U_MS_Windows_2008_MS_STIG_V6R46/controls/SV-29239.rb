control 'SV-29239' do
  title 'The user is allowed to launch Windows Messenger (MSN Messenger, .NET Messenger).'
  desc 'This setting prevents the Windows Messenger client from being run.  

Instant Messaging clients must be in compliance of with the Instant Messaging STIG.  Windows Messenger should not be active on Windows unless the instant messaging system is a Managed Enterprise Service for unclassified data for which the DAA has approved.'
  desc 'check', 'If the following registry value doesn’t exist or its value is not set to 1, then this is a finding:
Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Messenger\\Client\\
Value Name:	 PreventRun
Type:  REG_DWORD
Value:  1


Documentable Explanation: If the site has a requirement for Windows Messaging and meets the conditions of the Instant Messaging STIG this needs to be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Messenger “Do Not Allow Windows Messenger to be Run” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-546r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3348'
  tag rid: 'SV-29239r1_rule'
  tag gtitle: 'Windows Messenger - Do Not Allow To Run'
  tag fix_id: 'F-5827r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
