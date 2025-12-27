control 'SV-29243' do
  title 'Windows Messenger (MSN Messenger, .NET messenger) is run at system startup.'
  desc 'This setting prevents the automatic launch of Windows Messenger at user logon.  

Instant Messaging clients must be in compliance of with the Instant Messaging STIG.  Windows Messenger should not be active on Windows unless the instant messaging system is a Managed Enterprise Service for unclassified data for which the DAA has approved.'
  desc 'check', 'If the following registry value doesn’t exist or its value is not set to 1, then this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Messenger\\Client\\
Value Name:	 PreventAutoRun
Type:  REG_DWORD
Value:  1
 
Documentable Explanation: If the site has a requirement for Windows Messaging and meets the conditions of the Instant Messaging STIG this needs to be documented with the IAO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Messenger “Do Not Automatically Start Windows Messenger Initially” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-547r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3349'
  tag rid: 'SV-29243r1_rule'
  tag gtitle: 'Windows Messenger - Do Not Start Automatically'
  tag fix_id: 'F-5828r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
