control 'SV-40619' do
  title 'Logon options must be configured and enforced (Restricted Sites zone).'
  desc 'Users could submit credentials to servers operated by malicious people who could then attempt to connect to legitimate servers with those captured credentials.  Care must be taken with user credentials, automatic logon performance, and how default Windows credentials are passed to web sites.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Logon options" must be “Enabled” and "Anonymous logon" selected from the drop-down box. 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\4 

Criteria: If the value 1A00 is REG_DWORD = 196608 (decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Internet Control Panel -> Security Page -> Restricted Sites Zone -> "Logon options" to “Enabled” and select "Anonymous logon" from the drop-down box.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39362r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6311'
  tag rid: 'SV-40619r1_rule'
  tag stig_id: 'DTBI136'
  tag gtitle: 'DTBI136-User Authentication - Logon - Restricted'
  tag fix_id: 'F-34473r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
